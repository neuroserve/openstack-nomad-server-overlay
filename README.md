## Nomad server without Consul but on a defined.net overlay network

This repo sets up one Nomad server in one OpenStack environment. It uses [defined-systemd-units](https://github.com/quickvm/defined-systemd-units) to automatically install and enroll a host in an overlay network. 
We assume, that all Nomad servers in the overlay network get static IP addresses - that's why they are statically configured in the Nomad configuration. 

Nomad servers should not "unenroll" from the defined.net network. That's why you should set DN_SKIP_UNENROLL to "true". Ephemeral hosts should obviously "unenroll" during deletion. There you would set DN_SKIP_UNENROLL to "false".

Setting static IP addresses for the Nomad servers allows a static DNS configuration, too. This should make configuring Workload IDs in Nomad easier (without involving Consul). 
