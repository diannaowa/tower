package agent

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"

	"kubesphere.io/tower/pkg/utils"
	"kubesphere.io/tower/pkg/version"

	"github.com/jpillora/backoff"
	"sigs.k8s.io/controller-runtime/pkg/runtime/signals"
)

const (
	tokenFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	rootCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

var ErrNotInCluster = errors.New("unable to load in-cluster configuration, KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be defined")

type Agent struct {
	options   *Options
	sshConfig *ssh.ClientConfig
	sshConn   ssh.Conn
	config    *Config
}

func NewAgent(options *Options) (*Agent, error) {

	conf := &Config{
		Name:              options.Name,
		Token:             options.Token,
		KubeSphereSvcHost: options.KubesphereApiserverSvc,
		KubernetesSvcHost: options.KubernetesApiserverSvc,
		Version:           version.BuildVersion,
	}

	if options.Kubeconfig != "" {
		config, err := clientcmd.BuildConfigFromFlags("", options.Kubeconfig)
		if err != nil {
			klog.Error(err)
			return nil, err
		}

		conf.CAData = config.CAData
		conf.CertData = config.TLSClientConfig.CertData
		conf.KeyData = config.TLSClientConfig.KeyData
		conf.KubernetesSvcHost = strings.TrimPrefix(config.Host, "https://")
	} else {
		// Read in-cluster kubernetes config
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if len(host) == 0 || len(port) == 0 {
			return nil, ErrNotInCluster
		}

		token, err := ioutil.ReadFile(tokenFile)
		if err != nil {
			return nil, err
		}

		ca, err := ioutil.ReadFile(rootCAFile)
		if err != nil {
			return nil, err
		}

		conf.CAData = ca
		conf.BearerToken = token
		conf.KubernetesSvcHost = fmt.Sprintf("%s:%s", host, port)
	}

	agent := &Agent{
		options: options,
		config:  conf,
	}

	agent.sshConfig = &ssh.ClientConfig{
		User:            "",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		ClientVersion:   "SSH-" + version.ProtocolVersion + "-client",
		HostKeyCallback: agent.verifyServer,
		Timeout:         30 * time.Second,
	}

	return agent, nil
}

func (agent *Agent) Run() error {
	stopCh := signals.SetupSignalHandler()

	if agent.options.KeepAlive > 0 {
		go agent.keepAliveLoop(stopCh)
	}
	go agent.connectionLoop(stopCh)
	klog.Info("start agent successful.")

	<-stopCh
	klog.Info("stop agent.")
	return nil
}

func (agent *Agent) verifyServer(hostname string, remote net.Addr, key ssh.PublicKey) error {
	return nil
}

func (agent *Agent) Close() error {
	if agent.sshConn == nil {
		return nil
	}
	return agent.sshConn.Close()
}

func (agent *Agent) keepAliveLoop(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		default:
			time.Sleep(agent.options.KeepAlive)
			if agent.sshConn != nil {
				agent.sshConn.SendRequest("ping", true, nil)
			}
		}

	}
}

func (agent *Agent) connectionLoop(stopCh <-chan struct{}) {
	var connectionErr error
	b := &backoff.Backoff{
		Factor: 1.4, // for faster reconnection
		Max:    agent.options.MaxRetryInterval,
	}

	do := func() {
		if connectionErr != nil {
			attempt := int(b.Attempt())
			maxAttempt := agent.options.MaxRetryCount
			d := b.Duration()

			msg := fmt.Sprintf("Connection error: %s", connectionErr)
			if attempt > 0 {
				msg += fmt.Sprintf(" (Attempt: %d", attempt)
				if maxAttempt > 0 {
					msg += fmt.Sprintf("/%d", maxAttempt)
				}
				msg += ")"
			}
			klog.Warning(msg)

			if maxAttempt > 0 && attempt >= maxAttempt {
				klog.Fatal("retry count reach max attempt.")
			}
			klog.Warningf("Retrying in %s...", d)
			connectionErr = nil

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGHUP)
			select {
			case <-time.After(d):
			case <-sig:
			}
			signal.Stop(sig)
		}

		dialer := websocket.Dialer{
			ReadBufferSize:   1024,
			WriteBufferSize:  1024,
			HandshakeTimeout: 45 * time.Second,
			Subprotocols:     []string{version.ProtocolVersion},
			Proxy:            http.ProxyFromEnvironment,
		}

		wsHeaders := http.Header{}

		wsConn, _, err := dialer.Dial(agent.options.Server, wsHeaders)
		if err != nil {
			connectionErr = err
			return
		}

		conn := utils.NewWebSocketConn(wsConn)
		klog.V(4).Info("Handshaking...")
		sshConn, chans, reqs, err := ssh.NewClientConn(conn, "", agent.sshConfig)
		if err != nil {
			if strings.Contains(err.Error(), "unable to authenticate") {
				klog.Fatal("Authentication failed", err)
			} else {
				klog.Fatal(err)
			}
		}

		conf, _ := agent.config.Marshal()
		klog.V(4).Info("Sending config")
		t0 := time.Now()
		_, configErr, err := sshConn.SendRequest("config", true, conf)
		if err != nil {
			klog.Fatal("Config verification failed", err)
		}

		// we may encounter error like 'A session already allocated for this client.'
		// continue can be helpful while we execute 'kubectl rollout restart -n kubesphere-system deployment cluster-agent'
		// see issue #29
		if len(configErr) > 0 {
			connectionErr = errors.New(string(configErr))
			return
		}

		klog.V(2).Infof("Connected (Latency %s)", time.Since(t0))
		b.Reset()
		agent.sshConn = sshConn
		go ssh.DiscardRequests(reqs)
		go agent.connectStreams(chans)

		err = sshConn.Wait()
		agent.sshConn = nil
		if err != nil && err != io.EOF {
			connectionErr = err
			klog.Error(err)
			return
		}
		klog.V(2).Info("Disconnected")
	}

	for {
		select {
		case <-stopCh:
			return
		default:
			do()
		}
	}
}

func (agent *Agent) connectStreams(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		remote := string(ch.ExtraData())
		stream, reqs, err := ch.Accept()
		if err != nil {
			klog.Error("Failed to accept stream", err)
			continue
		}

		go ssh.DiscardRequests(reqs)
		go utils.HandleTCPStream(stream, remote)
	}
}
