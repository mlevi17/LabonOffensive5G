Vagrant.configure("2") do |config|

    # VM for attacker
    config.vm.define "attacker" do |attacker|
        attacker.vm.synced_folder "./tools", "/opt/tools" # shared folder for attack script
        attacker.vm.synced_folder "./attacker_webserver/www", "/var/www"  # shared folder for webserver 
        attacker.vm.synced_folder "./attacker_webserver/nginx_sites", "/home/vagrant/nginx_sites"
        attacker.vm.box = "kalilinux/rolling"
        attacker.vm.hostname = "attacker"
        attacker.vm.network "private_network", ip: "192.168.50.10"
        attacker.vm.provider "virtualbox" do |vb|
            vb.name = "attacker_vm"
            vb.memory = "2048"
            vb.cpus = 2
        end
        attacker.vm.provision "shell", path: "scripts/setup-attacker.sh"
    end

    #VM for victim
    config.vm.define "victim" do |victim|
        victim.vm.box = "ubuntu/focal64"
        victim.vm.hostname = "victim"
        victim.vm.network "private_network", ip: "192.168.50.20"
        victim.vm.provider "virtualbox" do |vb|
            vb.name = "victim_vm"
            vb.memory = "2048"
            vb.cpus = 1
        end
        victim.vm.provision "shell", path: "scripts/setup-victim.sh"
    end

    # VM for Server (Web Server & DNS)
    config.vm.define "server" do |server|
        server.vm.synced_folder "./DNS_server", "/home/vagrant/dns-config" # shared folder for dns server config file
        server.vm.synced_folder "./webserver/www", "/var/www"  # shared folder for webserver 
        server.vm.synced_folder "./webserver/nginx_sites", "/home/vagrant/nginx_sites"
        server.vm.box = "ubuntu/focal64"
        server.vm.hostname = "server"
        server.vm.network "private_network", ip: "192.168.50.30" # network for DNS server
        server.vm.network "private_network", ip: "192.168.50.40" # network for HTTP server
        server.vm.provider "virtualbox" do |vb|
            vb.name = "server_vm"
            vb.memory = "1024"
            vb.cpus = 1
        end
        server.vm.provision "shell", path: "scripts/setup-server.sh"
    end
end