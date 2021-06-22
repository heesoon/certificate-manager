Usage
============================

Source Tree
----------------------------------------
<pre>
<code>
    .
    ├── build-config
    │   └── img
    ├── files
    │   ├── conf
    │   │   └── pmlog
    │   ├── db8
    │   │   ├── kinds
    │   │   └── permissions
    │   ├── launch
    │   ├── schema
    │   ├── scripts
    │   └── sysbus
    ├── include
    │   ├── adapters
    │   └── ls-utils
    ├── src
    │   ├── adapters
    │   └── ls-utils
    └── tests

</code>
</pre>

Description of Source Tree
----------------------------------------
* build-config    
    - com.webos.service.certificatemanager.bb      
        - should copy to oe/build-signage/meta-lg-webos-id/meta-id/recipes-id/com.webos.service.certificateManager/
    - webos-local.conf     
        - should copy to oe/build-signage/

* files     
    - conf/pmlog      
        - configuration files for PmLog Setting
    - db8/kinds, db8/permission     
        - configuration files for db8 Setting       
    - launch      
        - configuration files for systemd Setting
    - schema     
        - schema       
    - scripts      
        - scripts to build PKI certificate chain
    - sysbus     
        - configuration files for luna service Setting          
     
Build Way
----------------------------------------
* actual certificate manager code location : describe in "webos-local.conf" file
    <pre>
    <code>
    INHERIT += "externalsrc"
    EXTERNALSRC_pn-com.webos.service.certificatemanager = "/data/heesoon.kim/project/certificate-manager/"
    EXTERNALSRC_BUILD_pn-com.webos.service.certificatemanager = "/data/heesoon.kim/project/certificate-manager/build/"
    PR_append_pn-com.webos.service.certificatemanager =".local0"
    </code>
    </pre>
* move to oe/build-signage/    
* excute oe enviroment apply
    - source oe-init-build-env
* execute command like lib32-(recipe name = com.webos.service.certificatemanager)
    - bitbake lib32-com.webos.service.certificatemanager      

Test Way
----------------------------------------
* preconditions 1(ubunt server 18.04 nfs configuration)     
    - nfs service install     
        - sudo apt-get install nfs-kernel-server    
    - nfs folder      
        - mkdir /home/hskim/nfsroot    
    - nfs folder permission change      
        - sudo chmod -R /home/hskim/nfsroot         
    - sudo vim /etc/exports      
        - /home/hskim/nfsroot/ *(rw,sync,nohide,no_root_squash,insecure,subtree_check)      
    - sudo vim /etc/default/nfs-kernel-server (optional)     
        - RPCNFSDOPTS="--nfs-version 2,3,4 --debug --syslog"  
    - nfs service restart      
        - sudo /etc/init.d/nfs-kernel-server restart
        - sudo /etc/init.d/rpcbind restart (optional)      

* preconditions 2(target)     
    - #nset (network setting)     
        - will you use DHCP? <y/N> N    
    - #nfsroot      
        - will you use nfsroot? <y/N> Y    
            - nfsserver : ubuntu server IP address      
            - nfsroot : /home/hskim/nfsroot/
            - nfs_usbeth: enter         
    - #set bootmode webos
    - #print on
    - #saveenv
    - #reset
    - dpm off
        - luna-send -n 1 luna://com.lge.settingsservice/setSystemSettings '{"category":"commercial","settings":{"dpmMode":"off"}}'

* preconditions 3     
    - bellow files in tests/ca/ should be copied to nfsroot/usr/palm/services/com.webos.service.certificatemanager/scripts folder of target (only for testing purpose)
    - customer_openssl.cnf (configuration file to generate customer certificate)  
    - intermediate.cert.pem (Intermediate CA certificate)
    - intermediate.key.pem (Intermediate CA private key)
    - ca-chain.cert.pem (Root CA + Intermediate CA certificate)

* generate luna test (customer keypair generation)
    - luna-send -n 1 -f luna://com.webos.service.certificatemanager/generateKey '{"keyname" : "test", "KeyFilename" : "/usr/palm/services/com.webos.service.certificatemanager/key.pem", "keySize" : 2048}'      

* csr luna test with customer_openssl.cnf (customer certificate csr)
    - luna-send -n 1 -f luna://com.webos.service.certificatemanager/csr '{"csrFilename" : "/usr/palm/services/com.webos.service.certificatemanager/csr.pem", "privateKey" : "/usr/palm/services/com.webos.service.certificatemanager/key.pem", "commonName" : "Customer Inc"}'     

* sign luna test with intermediate.key.pem
    - luna-send -n 1 -f luna://com.webos.service.certificatemanager/sign '{"certFilename" : "/usr/palm/services/com.webos.service.certificatemanager/signedCert.pem", "csrFilename" : "/usr/palm/services/com.webos.service.certificatemanager/csr.pem"}'

* verify luna test with ca-chain.cert.pem
    - luna-send -n 1 -f luna://com.webos.service.certificatemanager/verify '{"certFilename" : "/usr/palm/services/com.webos.service.certificatemanager/signedCert.pem"}'