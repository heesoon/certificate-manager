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
