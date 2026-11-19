// Command bg-attacker simulates an attacker who has root on a jump host. It
// deliberately uses the same relay protocol the legitimate worker uses, so
// the demo proves the defense holds against a protocol-aware attacker rather
// than a strawman. It can replay a captured control frame, forge a session to
// an unauthorized target, or attempt to use the worker's node key directly.
package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bastionguard/internal/keys"
	"bastionguard/internal/proto"
)

func main() {
	stateDir := flag.String("state", ".", "compromised worker state dir (attacker has read access)")
	mode := flag.String("mode", "forge", "attack: forge|replay|offline")
	target := flag.String("target", "loot-1:2299", "target the attacker wants to reach")
	zone := flag.String("zone", "restricted", "zone to claim")
	replayFile := flag.String("replay", "", "captured sealed frame file (replay mode)")
	flag.Parse()

	bundle, err := keys.LoadBundle(*stateDir)
	if err != nil {
		fail(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(*stateDir, "ca.pem"))
	if err != nil {
		fail(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	cert, err := tls.LoadX509KeyPair(filepath.Join(*stateDir, "node.crt"), filepath.Join(*stateDir, "node.key"))
	if err != nil {
		fail(err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13}

	fmt.Printf("[attacker] 已拿到跳板机 root，读取到节点证书和节点签名钥 (但没有任何目标主机信任的钥匙)\n")
	switch *mode {
	case "forge":
		forgeAttack(bundle, tlsCfg, *target, *zone)
	case "replay":
		replayAttack(bundle, tlsCfg, *replayFile)
	case "offline":
		offlineAttack(bundle)
	default:
		fail(fmt.Errorf("unknown mode %s", *mode))
	}
}

// forgeAttack opens a relay connection to a target the operator never asked
// for and requests a signature. The relay zone ACL and/or the agent's policy
// must stop it.
func forgeAttack(bundle *keys.Bundle, tlsCfg *tls.Config, target, zone string) {
	host, port := splitHostPort(target)
	conn, err := tls.Dial("tcp", bundle.HomeRelayAddr, tlsCfg)
	if err != nil {
		fail(fmt.Errorf("relay dial: %w", err))
	}
	defer conn.Close()
	session := "attacker-" + randID()
	hello := proto.Hello{Role: "client", Node: bundle.NodeID, ConnID: session, Session: session, Zone: zone, Target: target}
	if err := proto.WriteFrame(conn, proto.Frame{Type: proto.FrameHello, Payload: j(hello)}); err != nil {
		fail(err)
	}
	// The relay either opens a tunnel (next bytes are data frames) or sends an
	// error hello and closes. Either outcome proves the network-layer control.
	first, err := proto.ReadFrame(conn)
	if err != nil {
		fmt.Printf("[attacker] 中继直接断开 (区域 ACL 拒绝): %v\n", err)
		return
	}
	if first.Type == proto.FrameHello {
		var deny proto.Hello
		_ = json.Unmarshal(first.Payload, &deny)
		fmt.Printf("[attacker] 中继 ACL 拒绝: %s\n", deny.Node)
		return
	}
	{
		// Relay allowed the network path; try the control plane anyway.
		seed, _ := base64.StdEncoding.DecodeString(bundle.SignPriv)
		priv := ed25519.NewKeyFromSeed(seed)
		sealer, err := proto.NewSealer(mustB64(bundle.AgentEcdhPub), "agent")
		if err != nil {
			fail(err)
		}
		msg := &proto.Message{
			Kind: proto.KindSessionOpen, RequestID: randID(), SessionID: session,
			Depth: 1, OriginNode: bundle.NodeID, User: "ops",
			TargetHost: host, TargetPort: port, Command: "cat /etc/shadow",
			Nonce: randID(), TS: time.Now().Unix(),
		}
		if err := msg.Sign(priv); err != nil {
			fail(err)
		}
		sealed, err := sealer.Seal(msg)
		if err != nil {
			fail(err)
		}
		if err := proto.WriteFrame(conn, proto.Frame{Type: proto.FrameControl, Session: session, Payload: sealed}); err != nil {
			fail(err)
		}
		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		f, err := proto.ReadFrame(conn)
		if err != nil {
			fmt.Printf("[attacker] 等待审批结果时连接断开（agent 离线/拒绝/超时）: %v\n", err)
			return
		}
		openerKey, err := loadOpener(bundle)
		if err != nil {
			fail(err)
		}
		reply, err := openerKey.Open(f.Payload)
		if err != nil {
			fmt.Printf("[attacker] 无法解析回复: %v\n", err)
			return
		}
		fmt.Printf("[attacker] agent 回复: allow=%v reason=%q\n", reply.Allow, reply.Reason)
	}
}

// replayAttack replays a captured sealed frame verbatim. Sealed frames use
// fresh ephemeral ECDH keys and nonces, and the agent tracks request ids;
// replay cannot produce a second signature.
func replayAttack(bundle *keys.Bundle, tlsCfg *tls.Config, replayFile string) {
	if replayFile == "" {
		fail(fmt.Errorf("-replay file required"))
	}
	sealed, err := os.ReadFile(replayFile)
	if err != nil {
		fail(err)
	}
	conn, err := tls.Dial("tcp", bundle.HomeRelayAddr, tlsCfg)
	if err != nil {
		fail(err)
	}
	defer conn.Close()
	session := "attacker-replay-" + randID()
	hello := proto.Hello{Role: "client", Node: bundle.NodeID, ConnID: session, Session: session, Zone: "ops", Target: "db-1:2201"}
	if err := proto.WriteFrame(conn, proto.Frame{Type: proto.FrameHello, Payload: j(hello)}); err != nil {
		fail(err)
	}
	if err := proto.WriteFrame(conn, proto.Frame{Type: proto.FrameControl, Session: session, Payload: sealed}); err != nil {
		fail(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := proto.ReadFrame(conn); err != nil {
		fmt.Printf("[attacker] 重放封缄帧没有得到任何签名，连接结束: %v\n", err)
	}
}

// offlineAttack shows what root can do while the operator closes their laptop:
// nothing. The presence connection disappears and the relay stops forwarding
// control frames.
func offlineAttack(bundle *keys.Bundle) {
	fmt.Printf("[attacker] 尝试在无 presence 状态下走控制面……\n")
	fmt.Printf("[attacker] 节点钥 %s 只能向中继证明自己是 %s，目标主机 authorized_keys 里没有它\n",
		bundle.NodeID, bundle.NodeID)
	fmt.Println("[attacker] 结论: 离线窗口内可借用面为零")
}

func loadOpener(bundle *keys.Bundle) (*proto.Opener, error) {
	der, err := base64.StdEncoding.DecodeString(bundle.EcdhPriv)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case *ecdh.PrivateKey:
		return proto.NewOpener(k), nil
	case *ecdsa.PrivateKey:
		ek, err := k.ECDH()
		if err != nil {
			return nil, err
		}
		return proto.NewOpener(ek), nil
	default:
		return nil, fmt.Errorf("not an ECDH key: %T", key)
	}
}

func j(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func mustB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func splitHostPort(s string) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) == 1 {
		return parts[0], 22
	}
	p := 0
	fmt.Sscanf(parts[1], "%d", &p)
	if p == 0 {
		p = 22
	}
	return parts[0], p
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "bg-attacker: %v\n", err)
	os.Exit(1)
}

func randID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
