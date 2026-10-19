NetSPoC-Approve is part of the NetSPoC software suite. While the [NetSPoC core](https://github.com/hknutzen/Netspoc) calculates your device configs from a given input topology and rule set, Netspoc-Approve puts NetSPoCs output to good use by managing and applying the generated config files.

*****

Use NetSPoC-Approve to

- Store your NetSPoC generated config files as numbered policies within a given base directory. 
- Compare the newly generated policy to the state of your managed devices.
- Alter your devices according to the newest policy.
  

If you are part of a team with many contributors working on your input files,
you may find our NetSPoC-Approve tools for automation and user management helpful.

Run NetSPoC within its own user account to hide login data from single contributors. Let contributors conduct NetSPoC-Approve operations as user netspoc to make them audit-proof.

Automate policy generation, compression and deletion as well as config application and status examination of your devices by using our management scripts within your cron jobs.

*****

To use NetSPoC-Approve, you need to
- Make your NetSPoC input directory a git repo.
- Adapt the config file (see _Netspoc-Approve/etc/netspoc-approve_) to your needs and save within the suggested location. As a minimum, you need to specify your base directory and your NetSPoC input directory.
- Within your base dir, create the directories _policies_, _lock_, _status_ and _history_:
   - _/policies_ is going to contain your generated policies
   - _/status_ will monitor the state of your devices
   - _/lock_ keeps lockfiles to prevent update conflicts on your devices
   - _/history_ records the program calls affecting your devices
- Also within your base dir, set up a _credentials_ file to store the login data to your devices. NetSPoC-Approve expects 3 field lines containing following information:
  `<devicename> <username> <password>`     

Then calculate your policy by running:
`newpolicy.sh`

You will find the result within your _basedir/policies_ directory, with your first policy numbered p1, and a symlink _basedir/policy/current_ pointing to it.

Within your newly generated policy p1, you will find
- _/code_ holding the generated configurations for every managed device
- _/src_ containing the netspoc input version the code was generated from
- a logfile _compile.log_ containing the sterr/stdout output from running netspoc.  
 
To check whether the configuration running on your device differs from the configuration calculated within the latest policy, run: 
`do-approve compare $devicename`

To conduct any necessary alterations on your managed device, run:
`do-approve approve $devicename`

Check what happened during the latest compare or approve within _$basedir/policy/current/log_. You will find every step of the process logged in a specific file:

- _\<devicename>.login_ tracks signing in on the device
- _\<devicename>.config_ stores the devices running config
- _\<devicename>.change_ tracks the commands executed on the device 
- _\<devicename>.drc_ records all warnings and errors

*****

To set up a multi-user environment, set up an origin git repo to collaborate on your NetSPoC input files. Reference this repo as netspoc_git within your NetSPoC-Approve config file.

Create a new user netspoc and locate your base dir within its home directory.

Adjust _/etc/sudoers_ as suggested in _Netspoc-Approve/etc/sudoers_ 

Let your coworkers use our wrapper scripts `newpolicy`, `diamonds compare $device` and `diamonds approve $device` to have all actions conducted as user netspoc.

Use our scripts `approve-all` and `compare-all` to conduct approve or compare on all your managed devices.

Apply these and other scripts like `compress-policies` and `delete-old-policies` as cron jobs to ensure a stable and clean environment at all times. For specifications, alter the config file according to your needs.

*****

The main intention of NetSPoC-Approve is to keep the state of your managed devices clear and consistent. To ensure this, all compare and approve commands operate on the latest generated policy. You might however want to avoid that behaviour for troubleshooting or debugging. To conduct a compare or approve  with a NetSPoC generated config file that is not part of your latest policy, run drc:

`drc <path/to/configfile/$devicename>`
  
This will apply the given config file to your device. To compare the config file to the running config, use option -c.

You can also use drc to compare two different config files. To do so, hand both config files to drc:

`drc <path/to/configfile/$devicenameA> <path/to/configfile/$devicenameB>`

