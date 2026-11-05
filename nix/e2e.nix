{ pkgs, package }:
let
  ip = {
    coordinator = "203.0.113.1";
    stunAlternate = "203.0.113.2";
    home = "198.51.100.10";
    aws = "192.0.2.10";
  };
  addresses = {
    coordinator = [
      ip.coordinator
      ip.stunAlternate
    ];
    home = [ ip.home ];
    aws = [ ip.aws ];
  };

  secrets =
    pkgs.runCommand "vibemaxxer-e2e-secrets"
      {
        nativeBuildInputs = [
          pkgs.openssh
          pkgs.openssl
        ];
      }
      ''
        mkdir $out
        for key in home aws-host; do
          ssh-keygen -q -t ed25519 -N "" -C $key -f $out/$key
        done
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
          -subj /CN=vibemaxxer-e2e -keyout $out/tls.key -out $out/tls.crt \
          -addext "subjectAltName=DNS:direct.example,DNS:blocked.example,DNS:proxied.example,DNS:*.proxied.example,DNS:denied.example,DNS:sneaky.example"
      '';

  publicAddress = name: {
    networking.interfaces.eth1.ipv4 = {
      addresses = map (address: {
        inherit address;
        prefixLength = 32;
      }) addresses.${name};
      routes = map (address: {
        inherit address;
        prefixLength = 32;
        options.src = builtins.head addresses.${name};
      }) (pkgs.lib.flatten (builtins.attrValues (removeAttrs addresses [ name ])));
    };
  };

  service = description: command: {
    inherit description;
    wantedBy = [ "multi-user.target" ];
    unitConfig.StartLimitIntervalSec = 0;
    serviceConfig = {
      ExecStart = command;
      Restart = "always";
      RestartSec = 2;
    };
  };

  frpc =
    extra:
    pkgs.writeText "frpc.toml" ''
      serverAddr = "${ip.coordinator}"
      serverPort = 7000
      auth.token = "e2e-coordinator-token"
      natHoleStunServer = "${ip.coordinator}:3478"
      ${extra}
    '';

  standaloneRules = pkgs.writeText "filter.rules" ''
    block .blocked.example
  '';

  clientRules = pkgs.writeText "client.rules" ''
    block .blocked.example
    proxy .proxied.example
    proxy denied.example
    proxy sneaky.example
  '';

  serverRules = pkgs.writeText "server.rules" ''
    allow .proxied.example 80,443
    allow sneaky.example   80,443
    deny  secret.proxied.example
  '';
in
{
  name = "vibemaxxer-e2e";

  nodes = {
    coordinator = {
      imports = [ (publicAddress "coordinator") ];
      networking.firewall = {
        allowedTCPPorts = [
          80
          443
          3478
          7000
        ];
        allowedUDPPorts = [
          3478
          3479
        ];
      };
      systemd.services.frps = service "frp coordinator" "${pkgs.frp}/bin/frps -c ${pkgs.writeText "frps.toml" ''
        bindAddr = "${ip.coordinator}"
        bindPort = 7000
        auth.token = "e2e-coordinator-token"
      ''}";
      services.coturn = {
        enable = true;
        no-auth = true;
        extraConfig = "stun-only\nrfc5780";
        listening-ips = addresses.coordinator;
      };
      services.nginx = {
        enable = true;
        virtualHosts.origin = {
          default = true;
          addSSL = true;
          sslCertificate = "${secrets}/tls.crt";
          sslCertificateKey = "${secrets}/tls.key";
          locations."/".return = "200 '$remote_addr $host\\n'";
        };
      };
    };

    aws = {
      imports = [ (publicAddress "aws") ];
      environment.systemPackages = [ pkgs.curl ];
      networking.hosts = {
        ${ip.coordinator} = [
          "proxied.example"
          "www.proxied.example"
          "secret.proxied.example"
          "denied.example"
        ];
        "127.0.0.1" = [ "sneaky.example" ];
      };
      environment.etc."ssh/ssh_host_ed25519_key" = {
        source = "${secrets}/aws-host";
        mode = "0600";
      };
      services.openssh = {
        enable = true;
        openFirewall = false;
        hostKeys = [ ];
        extraConfig = ''
          HostKey /etc/ssh/ssh_host_ed25519_key
          Match User proxy-tunnel
              PubkeyAuthentication yes
              PasswordAuthentication no
              KbdInteractiveAuthentication no
              AllowTcpForwarding local
              PermitOpen 127.0.0.1:8081
              AllowStreamLocalForwarding no
              MaxSessions 0
              PermitTTY no
              AllowAgentForwarding no
              X11Forwarding no
              PermitTunnel no
        '';
      };
      users.groups.proxy-tunnel = { };
      users.users.proxy-tunnel = {
        isSystemUser = true;
        group = "proxy-tunnel";
        openssh.authorizedKeys.keyFiles = [ "${secrets}/home.pub" ];
      };
      systemd.services.vibemaxxer-server = service "vibemaxxer server" "${package}/bin/vibemaxxer server --rules ${serverRules}";
      systemd.services.frpc = service "frp agent exposing sshd over XTCP" "${pkgs.frp}/bin/frpc -c ${frpc ''
        [[proxies]]
        name = "aws-ssh"
        type = "xtcp"
        secretKey = "e2e-xtcp-secret"
        localIP = "127.0.0.1"
        localPort = 22
      ''}";
    };

    home = {
      imports = [ (publicAddress "home") ];
      environment.systemPackages = [ pkgs.curl ];
      networking.hosts.${ip.coordinator} = [
        "direct.example"
        "blocked.example"
      ];
      environment.etc."vibemaxxer/id_ed25519" = {
        source = "${secrets}/home";
        mode = "0600";
      };
      programs.ssh.knownHosts.aws-vm-proxy.publicKeyFile = "${secrets}/aws-host.pub";
      programs.ssh.extraConfig = ''
        Host aws-proxy-tunnel
            HostName 127.0.0.1
            Port 2222
            User proxy-tunnel
            IdentityFile /etc/vibemaxxer/id_ed25519
            IdentitiesOnly yes
            HostKeyAlias aws-vm-proxy
            StrictHostKeyChecking yes
            BatchMode yes
            LocalForward 127.0.0.1:18080 127.0.0.1:8081
            ExitOnForwardFailure yes
            ServerAliveInterval 5
            ServerAliveCountMax 2
            ConnectTimeout 30
            RequestTTY no
      '';
      systemd.services.frpc = service "frp XTCP visitor for the AWS sshd" "${pkgs.frp}/bin/frpc -c ${frpc ''
        [[visitors]]
        name = "aws-ssh-visitor"
        type = "xtcp"
        serverName = "aws-ssh"
        secretKey = "e2e-xtcp-secret"
        bindAddr = "127.0.0.1"
        bindPort = 2222
      ''}";
      systemd.services.ssh-tunnel = service "SSH forward to the AWS vibemaxxer server" "${pkgs.openssh}/bin/ssh -N aws-proxy-tunnel";
      systemd.services.vibemaxxer-filter = service "standalone vibemaxxer client" "${package}/bin/vibemaxxer client --rules ${standaloneRules} --listen 127.0.0.1:8082";
      systemd.services.vibemaxxer-client = service "vibemaxxer client" "${package}/bin/vibemaxxer client --rules ${clientRules} --upstream 127.0.0.1:18080";
    };
  };

  testScript = ''
    from datetime import timedelta

    HOME, AWS = "${ip.home}", "${ip.aws}"
    CURL = "curl -sS --max-time 60 -x http://127.0.0.1:8080 --cacert ${secrets}/tls.crt"
    LOCAL_CURL = CURL.replace(":8080", ":8082")
    SSH = ("ssh -F /dev/null -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes "
           "-o ConnectTimeout=30 -o HostKeyAlias=aws-vm-proxy -i /etc/vibemaxxer/id_ed25519 ")
    TARGET = " proxy-tunnel@127.0.0.1"
    UDP_BLOCK = [
        "iptables ACTION INPUT -p udp ! -s 203.0.113.0/24",
        "iptables ACTION OUTPUT -p udp ! -d 203.0.113.0/24",
        "ip6tables ACTION INPUT -p udp",
        "ip6tables ACTION OUTPUT -p udp",
    ]

    def egress(url, curl=CURL):
        return home.succeed(f"{curl} {url}").split()[0]

    def refused(url, status, proxy_status, curl=CURL):
        out = home.fail(f"{curl} -fv -o /dev/null {url} 2>&1")
        assert f" {status} " in out, out
        assert f"Proxy-Status: {proxy_status}" in out, out

    start_all()
    coordinator.wait_for_unit("frps.service")
    coordinator.wait_for_unit("coturn.service")
    coordinator.wait_for_unit("nginx.service")
    aws.wait_for_unit("vibemaxxer-server.service")
    aws.wait_for_unit("sshd.service")
    aws.wait_for_unit("frpc.service")
    home.wait_for_unit("vibemaxxer-client.service")
    home.wait_for_unit("vibemaxxer-filter.service")

    with subtest("standalone filtering needs no upstream or tunnel"):
        home.systemctl("stop ssh-tunnel.service frpc.service")
        home.fail("ss -ltnH 'sport = 18080' | grep -q .")
        assert egress("http://direct.example/", LOCAL_CURL) == HOME
        assert egress("https://direct.example/", LOCAL_CURL) == HOME
        refused("http://blocked.example/", 403, "vibemaxxer-client; error=http_request_denied", LOCAL_CURL)
        refused("https://x.blocked.example/", 403, "vibemaxxer-client; error=http_request_denied", LOCAL_CURL)
        coordinator.fail("grep -q blocked.example /var/log/nginx/access.log")

    home.systemctl("start frpc.service ssh-tunnel.service")
    home.wait_for_unit("ssh-tunnel.service")

    with subtest("the AWS VM accepts no inbound connections"):
        home.fail("timeout 5 bash -c '</dev/tcp/${ip.aws}/22'")
        coordinator.fail("timeout 5 bash -c '</dev/tcp/${ip.aws}/22'")

    with subtest("SSH forward comes up over the XTCP path"):
        home.wait_until_succeeds("ss -ltnH 'sport = 18080' | grep -q 127.0.0.1", timeout=timedelta(minutes=3))

    with subtest("DIRECT domains exit from home"):
        assert egress("https://direct.example/") == HOME
        assert egress("http://direct.example/") == HOME

    with subtest("PROXY domains resolve and exit on AWS"):
        home.fail("getent hosts proxied.example")
        home.wait_until_succeeds(f"{CURL} https://proxied.example/ | grep -q '^{AWS} '", timeout=timedelta(minutes=1))
        assert egress("https://www.proxied.example/") == AWS
        assert egress("http://www.proxied.example/?token=hunter2") == AWS

    with subtest("client BLOCK opens no connection"):
        refused("https://blocked.example/", 403, "vibemaxxer-client; error=http_request_denied")
        refused("http://x.blocked.example/", 403, "vibemaxxer-client; error=http_request_denied")
        coordinator.fail("grep -q blocked.example /var/log/nginx/access.log")
        aws.fail("journalctl -u vibemaxxer-server | grep -q blocked.example")

    with subtest("AWS policy is enforced independently"):
        refused("https://denied.example/", 403, "vibemaxxer-server; error=http_request_denied")
        refused("https://secret.proxied.example/", 403, "vibemaxxer-server; error=http_request_denied")
        refused("http://proxied.example:8080/", 403, "vibemaxxer-server; error=http_request_denied")
        refused("https://sneaky.example/", 403, "vibemaxxer-server; error=destination_ip_prohibited")
        refused("https://${ip.coordinator}/", 403, "vibemaxxer-client; error=destination_ip_prohibited")
        coordinator.fail("grep -q denied.example /var/log/nginx/access.log")

    with subtest("logs carry decisions but not queries"):
        logs = home.succeed("journalctl -u vibemaxxer-client")
        assert "host=proxied.example port=443 action=proxy rule=/nix/store/" in logs, logs
        assert "-client.rules:2 status=200" in logs, logs
        assert "hunter2" not in logs + aws.succeed("journalctl -u vibemaxxer-server")

    with subtest("the tunnel account only reaches the proxy"):
        home.succeed(f"{SSH} -W 127.0.0.1:8081 {TARGET} </dev/null")
        home.fail(f"{SSH} -W 127.0.0.1:22 {TARGET} </dev/null")
        home.fail(f"{SSH} {TARGET} true")
        home.fail(f"{SSH} -s {TARGET} sftp </dev/null")
        home.fail(f"timeout 60 {SSH} -N -o ExitOnForwardFailure=yes -R 127.0.0.1:9999:127.0.0.1:22 {TARGET}")

    with subtest("without a direct path PROXY fails and DIRECT keeps working"):
        for rule in UDP_BLOCK:
            aws.succeed(f"{rule.replace('ACTION', '-I')} -j DROP")
        since = home.succeed("date +%s").strip()
        aws.systemctl("restart frpc.service")
        home.systemctl("restart frpc.service")
        home.wait_until_succeeds(
            f"journalctl -u frpc --since=@{since} | grep -q 'open tunnel error'", timeout=timedelta(minutes=2)
        )
        home.fail("ss -ltnH 'sport = 18080' | grep -q .")
        out = home.fail(f"{CURL} -w '%{{http_connect}}' -o /dev/null https://proxied.example/ 2>&1")
        assert "502" in out or "504" in out, out
        assert egress("https://direct.example/") == HOME

    with subtest("PROXY recovers once the direct path returns"):
        for rule in UDP_BLOCK:
            aws.succeed(f"{rule.replace('ACTION', '-D')} -j DROP")
        home.wait_until_succeeds(f"{CURL} https://proxied.example/ | grep -q '^{AWS} '", timeout=timedelta(minutes=3))

    with subtest("LAN TLS works without SSH or frp"):
        home.systemctl("stop ssh-tunnel.service frpc.service")
        aws.systemctl("stop frpc.service")
        aws.succeed("iptables -I INPUT -s ${ip.home} -p tcp --dport 8443 -j ACCEPT")
        binary = "${package}/bin/vibemaxxer"
        home_pin = home.succeed(f"{binary} key --key /tmp/home-lan.pem").strip()
        aws_pin = aws.succeed(f"{binary} key --key /tmp/aws-lan.pem").strip()
        aws.succeed(f"systemd-run --unit=vibemaxxer-lan-server {binary} server --tls "
                    f"--listen {AWS}:8443 --key /tmp/aws-lan.pem --client-key {home_pin} --rules ${serverRules}")
        aws.wait_for_unit("vibemaxxer-lan-server.service")
        home.succeed(f"systemd-run --unit=vibemaxxer-lan-client {binary} client "
                     f"--listen 127.0.0.1:8083 --key /tmp/home-lan.pem --server {AWS}:8443 "
                     f"--server-key {aws_pin} --rules ${clientRules}")
        home.wait_for_open_port(8083)
        LAN_CURL = CURL.replace(":8080", ":8083")
        home.fail("getent hosts proxied.example")
        assert egress("https://proxied.example/", LAN_CURL) == AWS
        assert egress("http://www.proxied.example/", LAN_CURL) == AWS
        assert egress("https://direct.example/", LAN_CURL) == HOME
        refused("https://blocked.example/", 403, "vibemaxxer-client; error=http_request_denied", LAN_CURL)
        refused("https://denied.example/", 403, "vibemaxxer-server; error=http_request_denied", LAN_CURL)
        refused("https://sneaky.example/", 403, "vibemaxxer-server; error=destination_ip_prohibited", LAN_CURL)

    with subtest("LAN TLS pins fail closed"):
        for name, key, pin in [("bad-pin", "/tmp/home-lan.pem", "0" * 64),
                               ("unknown-client", "/tmp/unknown-lan.pem", aws_pin)]:
            home.succeed(f"systemd-run --unit=vibemaxxer-lan-{name} {binary} client "
                         f"--listen 127.0.0.1:8084 --key {key} --server {AWS}:8443 "
                         f"--server-key {pin} --rules ${clientRules}")
            home.wait_for_open_port(8084)
            bad_curl = CURL.replace(":8080", ":8084")
            refused("https://proxied.example/", 502, "vibemaxxer-client; error=destination_unavailable", bad_curl)
            refused("http://proxied.example/", 502, "vibemaxxer-client; error=destination_unavailable", bad_curl)
            assert egress("https://direct.example/", bad_curl) == HOME
            home.systemctl(f"stop vibemaxxer-lan-{name}.service")

    with subtest("LAN server loss never falls back to DIRECT"):
        aws.systemctl("stop vibemaxxer-lan-server.service")
        refused("https://proxied.example/", 502, "vibemaxxer-client; error=destination_unavailable", LAN_CURL)
        assert egress("https://direct.example/", LAN_CURL) == HOME
  '';
}
