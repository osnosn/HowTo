## [OpenWrt: enable hardware NAT and BBR on Newifi D1 or D2](https://github.com/osnosn/HowTo/blob/master/OpenWRT/Newifi_D1_D2_enable_hardware_NAT_and_BBR.md)

Written in 2019-09-27.

### Enable mt7621 hw_nat (newifi D1 or newifi D2)
`newifi mini` use mt7620, no hw_nat.   
login router's web.   
Network -> Firewall -> General Settings -> Software flow offloading(select) -> Hardware flow offloading(select) -> Save&Apply(submit)
> <img src="https://github.com/osnosn/HowTo/raw/master/OpenWRT/images/mt7621-nat1.png" width="100" /> <img src="https://github.com/osnosn/HowTo/raw/master/OpenWRT/images/mt7621-nat2.png" width="100" />

-----
### Enable TCP-BBR
You can choose whether to enable BBR or not.   
`opkg install kmod-tcp-bbr`   
it will enabled after reboot.    
