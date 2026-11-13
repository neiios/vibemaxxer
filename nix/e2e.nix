{ pkgs, package }:
let
  ip = {
    origin = "203.0.113.1";
    home = "198.51.100.10";
    aws = "192.0.2.10";
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
      addresses = [
        {
          address = ip.${name};
          prefixLength = 32;
        }
      ];
      routes = map (address: {
        inherit address;
        prefixLength = 32;
        options.src = ip.${name};
      }) (builtins.attrValues (removeAttrs ip [ name ]));
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

  standaloneRules = pkgs.writeText "filter.rules" ''
    block .blocked.example
    block localhost 9000
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
    origin = {
      imports = [ (publicAddress "origin") ];
      networking.firewall.allowedTCPPorts = [
        80
        443
      ];
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
        ${ip.origin} = [
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
        hostKeys = [ ];
        extraConfig = "HostKey /etc/ssh/ssh_host_ed25519_key";
      };
      users.groups.proxy-tunnel = { };
      users.users.proxy-tunnel = {
        isSystemUser = true;
        group = "proxy-tunnel";
        openssh.authorizedKeys.keyFiles = [ "${secrets}/home.pub" ];
      };
      systemd.services.vibemaxxer-server = service "vibemaxxer server" "${package}/bin/vibemaxxer server --rules ${serverRules}";
    };

    home = {
      imports = [ (publicAddress "home") ];
      environment.systemPackages = [ pkgs.curl ];
      networking.hosts = {
        ${ip.origin} = [
          "direct.example"
          "blocked.example"
        ];
        "127.0.0.1" = [ "rebind.example" ];
      };
      environment.etc."vibemaxxer/id_ed25519" = {
        source = "${secrets}/home";
        mode = "0600";
      };
      programs.ssh.knownHosts.aws-vm-proxy.publicKeyFile = "${secrets}/aws-host.pub";
      programs.ssh.extraConfig = ''
        Host aws-proxy-tunnel
            HostName ${ip.aws}
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
      systemd.services.ssh-tunnel = service "SSH forward to the AWS vibemaxxer server" "${pkgs.openssh}/bin/ssh -N aws-proxy-tunnel";
      systemd.services.local-web = service "web server for loopback tests" "${pkgs.python3}/bin/python3 -m http.server --bind :: --directory /var/empty 9000";
      systemd.services.vibemaxxer-filter = service "standalone vibemaxxer client" "${package}/bin/vibemaxxer client --rules ${standaloneRules} --listen 127.0.0.1:8082";
      systemd.services.vibemaxxer-client = service "vibemaxxer client" "${package}/bin/vibemaxxer client --rules ${clientRules} --upstream 127.0.0.1:18080";
    };
  };

  testScript = ''
    from datetime import timedelta

    HOME, AWS = "${ip.home}", "${ip.aws}"
    CURL = "curl -sS --max-time 60 -x http://127.0.0.1:8080 --cacert ${secrets}/tls.crt"
    LOCAL_CURL = CURL.replace(":8080", ":8082")

    def egress(url, curl=CURL):
        return home.succeed(f"{curl} {url}").split()[0]

    def refused(url, status, proxy_status, curl=CURL):
        out = home.fail(f"{curl} -fv -o /dev/null {url} 2>&1")
        assert f" {status} " in out, out
        assert f"Proxy-Status: {proxy_status}" in out, out

    start_all()
    origin.wait_for_unit("nginx.service")
    aws.wait_for_unit("vibemaxxer-server.service")
    aws.wait_for_unit("sshd.service")
    home.wait_for_unit("vibemaxxer-client.service")
    home.wait_for_unit("vibemaxxer-filter.service")

    with subtest("standalone filtering needs no upstream or tunnel"):
        home.systemctl("stop ssh-tunnel.service")
        home.fail("ss -ltnH 'sport = 18080' | grep -q .")
        assert egress("http://direct.example/", LOCAL_CURL) == HOME
        assert egress("https://direct.example/", LOCAL_CURL) == HOME
        refused("http://blocked.example/", 403, "vibemaxxer-client; error=http_request_denied", LOCAL_CURL)
        refused("https://x.blocked.example/", 403, "vibemaxxer-client; error=http_request_denied", LOCAL_CURL)
        for url in ["http://localhost:9000/", "http://127.0.0.1:9000/", "http://[::1]:9000/", "http://app.localhost:9000/"]:
            refused(url, 403, "vibemaxxer-client; error=http_request_denied", LOCAL_CURL)
        origin.fail("grep -q blocked.example /var/log/nginx/access.log")

    home.systemctl("start ssh-tunnel.service")

    with subtest("SSH forward comes up"):
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
        origin.fail("grep -q blocked.example /var/log/nginx/access.log")
        aws.fail("journalctl -u vibemaxxer-server | grep -q blocked.example")

    with subtest("vibemaxxer run sends loopback through the client"):
        RUN = "VIBEMAXXER_RUN_SCOPE=1 NO_PROXY='*' ${package}/bin/vibemaxxer run -- curl -sS --max-time 60 --cacert ${secrets}/tls.crt"
        home.wait_for_open_port(9000)
        for url in ["http://127.0.0.1:9000/", "http://localhost:9000/", "http://[::1]:9000/"]:
            assert home.succeed(f"{RUN} -o /dev/null -w '%{{http_code}}' {url}") == "200", url
        logs = home.succeed("journalctl -u vibemaxxer-client")
        assert "host=localhost port=9000 action=direct rule=default status=200" in logs, logs
        refused("https://blocked.example/", 403, "vibemaxxer-client; error=http_request_denied", RUN)
        refused("http://rebind.example:9000/", 403, "vibemaxxer-client; error=destination_ip_prohibited", RUN)

    with subtest("AWS policy is enforced independently"):
        refused("https://denied.example/", 403, "vibemaxxer-server; error=http_request_denied")
        refused("https://secret.proxied.example/", 403, "vibemaxxer-server; error=http_request_denied")
        refused("http://proxied.example:8080/", 403, "vibemaxxer-server; error=http_request_denied")
        refused("https://sneaky.example/", 403, "vibemaxxer-server; error=destination_ip_prohibited")
        refused("https://${ip.origin}/", 403, "vibemaxxer-client; error=destination_ip_prohibited")
        origin.fail("grep -q denied.example /var/log/nginx/access.log")

    with subtest("logs carry decisions but not queries"):
        logs = home.succeed("journalctl -u vibemaxxer-client")
        assert "host=proxied.example port=443 action=proxy rule=/nix/store/" in logs, logs
        assert "-client.rules:2 status=200" in logs, logs
        assert "hunter2" not in logs + aws.succeed("journalctl -u vibemaxxer-server")

    with subtest("without the tunnel PROXY fails and DIRECT keeps working"):
        home.systemctl("stop ssh-tunnel.service")
        home.fail("ss -ltnH 'sport = 18080' | grep -q .")
        out = home.fail(f"{CURL} -w '%{{http_connect}}' -o /dev/null https://proxied.example/ 2>&1")
        assert "502" in out or "504" in out, out
        assert egress("https://direct.example/") == HOME

    with subtest("PROXY recovers once the tunnel returns"):
        home.systemctl("start ssh-tunnel.service")
        home.wait_until_succeeds(f"{CURL} https://proxied.example/ | grep -q '^{AWS} '", timeout=timedelta(minutes=3))

    with subtest("LAN TLS works without SSH"):
        home.systemctl("stop ssh-tunnel.service")
        aws.succeed("iptables -I INPUT -s ${ip.home} -p tcp --dport 8443 -j ACCEPT")
        binary = "${package}/bin/vibemaxxer"
        home_pin = home.succeed(f"{binary} key --key /tmp/home-lan.pem").strip()
        aws_pin = aws.succeed(f"{binary} key --key /tmp/aws-lan.pem").strip()
        aws.succeed(f"systemd-run --unit=vibemaxxer-lan-server {binary} server "
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
