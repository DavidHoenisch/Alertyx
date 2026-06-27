# frozen_string_literal: true
# Alertyx integration test matrix — real kernels for eBPF validation.
#
# Usage:
#   vagrant up ubuntu-22
#   vagrant ssh ubuntu-22 -c "cd /vagrant && sudo go test -tags=integration ./..."
#
# Distros:
#   ubuntu-22  Ubuntu 22.04 LTS  (kernel 5.15)
#   ubuntu-24  Ubuntu 24.04 LTS  (kernel 6.8)
#   fedora-40  Fedora 40          (kernel 6.8+)
#   arch       Arch Linux         (kernel 7.x)

PROVISION_SCRIPT = "test/integration/provision.sh"

Vagrant.configure("2") do |config|
  config.vm.synced_folder ".", "/vagrant", mount_options: ["rw"]

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
  end

  config.vm.define "ubuntu-22", primary: true do |node|
    node.vm.box = "ubuntu/jammy64"
    node.vm.hostname = "alertyx-ubuntu-22"
    node.vm.provision "shell", path: PROVISION_SCRIPT, privileged: true
  end

  config.vm.define "ubuntu-24" do |node|
    node.vm.box = "ubuntu/noble64"
    node.vm.hostname = "alertyx-ubuntu-24"
    node.vm.provision "shell", path: PROVISION_SCRIPT, privileged: true
  end

  config.vm.define "fedora-40" do |node|
    node.vm.box = "generic/fedora40"
    node.vm.hostname = "alertyx-fedora-40"
    node.vm.provision "shell", path: PROVISION_SCRIPT, privileged: true
  end

  config.vm.define "arch" do |node|
    node.vm.box = "archlinux/archlinux"
    node.vm.hostname = "alertyx-arch"
    node.vm.provision "shell", path: PROVISION_SCRIPT, privileged: true
  end
end
