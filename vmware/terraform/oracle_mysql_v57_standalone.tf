# =================================================================
# Licensed Materials - Property of IBM
# 5737-E67
# @ Copyright IBM Corporation 2016, 2017 All Rights Reserved
# US Government Users Restricted Rights - Use, duplication or disclosure
# restricted by GSA ADP Schedule Contract with IBM Corp.
# =================================================================

# This is a terraform generated template generated from oracle_mysql_v57_standalone

##############################################################
# Keys - CAMC (public/private) & optional User Key (public) 
##############################################################
variable "user_public_ssh_key" {
  type = "string"
  description = "User defined public SSH key used to connect to the virtual machine. The format must be in openSSH."
  default = "None"
}

variable "ibm_pm_public_ssh_key" {
  description = "Public CAMC SSH key value which is used to connect to a guest, used on VMware only."
}

variable "ibm_pm_private_ssh_key" {
  description = "Private CAMC SSH key (base64 encoded) used to connect to the virtual guest."
}

variable "allow_unverified_ssl" {
  description = "Communication with vsphere server with self signed certificate"
  default = "true"
}

##############################################################
# Define the vsphere provider 
##############################################################
provider "vsphere" {
  allow_unverified_ssl = "${var.allow_unverified_ssl}"
}

resource "random_id" "stack_id" {
  byte_length = "16"
}

##############################################################
# Define pattern variables 
##############################################################
##### unique stack name #####
variable "ibm_stack_name" {
  description = "A unique stack name."
}

#### Default OS Admin User Map ####

##### Environment variables #####
#Variable : ibm_pm_access_token
variable "ibm_pm_access_token" {
  type = "string"
  description = "IBM Pattern Manager Access Token"
}

#Variable : ibm_pm_service
variable "ibm_pm_service" {
  type = "string"
  description = "IBM Pattern Manager Service"
}

#Variable : ibm_sw_repo
variable "ibm_sw_repo" {
  type = "string"
  description = "IBM Software Repo Root (https://<hostname>:<port>)"
}

#Variable : ibm_sw_repo_password
variable "ibm_sw_repo_password" {
  type = "string"
  description = "IBM Software Repo Password"
}

#Variable : ibm_sw_repo_user
variable "ibm_sw_repo_user" {
  type = "string"
  description = "IBM Software Repo Username"
  default = "repouser"
}


##### MySQLNode01 variables #####
#Variable : MySQLNode01-image
variable "MySQLNode01-image" {
  type = "string"
  description = "Operating system image id / template that should be used when creating the virtual image"
}

#Variable : MySQLNode01-name
variable "MySQLNode01-name" {
  type = "string"
  description = "Short hostname of virtual machine"
}

#Variable : MySQLNode01-os_admin_user
variable "MySQLNode01-os_admin_user" {
  type = "string"
  description = "Name of the admin user account in the virtual machine that will be accessed via SSH"
}

#Variable : MySQLNode01_mysql_config_data_dir
variable "MySQLNode01_mysql_config_data_dir" {
  type = "string"
  description = "Directory to store information managed by MySQL server"
  default = "/var/lib/mysql"
}

#Variable : MySQLNode01_mysql_config_databases_database_1_database_name
variable "MySQLNode01_mysql_config_databases_database_1_database_name" {
  type = "string"
  description = "Create a sample database in MySQL"
  default = "default_database"
}

#Variable : MySQLNode01_mysql_config_databases_database_1_users_user_1_name
variable "MySQLNode01_mysql_config_databases_database_1_users_user_1_name" {
  type = "string"
  description = "Name of the first user which is created and allowed to access the created sample database "
  default = "defaultUser"
}

#Variable : MySQLNode01_mysql_config_databases_database_1_users_user_1_password
variable "MySQLNode01_mysql_config_databases_database_1_users_user_1_password" {
  type = "string"
  description = "Password of the first user"
}

#Variable : MySQLNode01_mysql_config_databases_database_1_users_user_2_name
variable "MySQLNode01_mysql_config_databases_database_1_users_user_2_name" {
  type = "string"
  description = "Name of the second user which is created and allowed to access the created sample database"
  default = "defaultUser2"
}

#Variable : MySQLNode01_mysql_config_databases_database_1_users_user_2_password
variable "MySQLNode01_mysql_config_databases_database_1_users_user_2_password" {
  type = "string"
  description = "Password of the second user"
}

#Variable : MySQLNode01_mysql_config_log_file
variable "MySQLNode01_mysql_config_log_file" {
  type = "string"
  description = "Log file configured in MySQL"
  default = "/var/log/mysqld.log"
}

#Variable : MySQLNode01_mysql_config_port
variable "MySQLNode01_mysql_config_port" {
  type = "string"
  description = "Listen port to be configured in MySQL"
  default = "3306"
}

#Variable : MySQLNode01_mysql_install_from_repo
variable "MySQLNode01_mysql_install_from_repo" {
  type = "string"
  description = "Install MySQL from secure repository server or yum repo"
  default = "true"
}

#Variable : MySQLNode01_mysql_os_users_daemon_gid
variable "MySQLNode01_mysql_os_users_daemon_gid" {
  type = "string"
  description = "Group ID of the default OS user to be used to configure MySQL"
  default = "mysql"
}

#Variable : MySQLNode01_mysql_os_users_daemon_home
variable "MySQLNode01_mysql_os_users_daemon_home" {
  type = "string"
  description = "Home directory of the default OS user to be used to configure MySQL"
  default = "/home/mysql"
}

#Variable : MySQLNode01_mysql_os_users_daemon_ldap_user
variable "MySQLNode01_mysql_os_users_daemon_ldap_user" {
  type = "string"
  description = "A flag which indicates whether to create the MQ USer locally, or utilise an LDAP based user."
  default = "false"
}

#Variable : MySQLNode01_mysql_os_users_daemon_name
variable "MySQLNode01_mysql_os_users_daemon_name" {
  type = "string"
  description = "User Name of the default OS user to be used to configure MySQL"
  default = "mysql"
}

#Variable : MySQLNode01_mysql_os_users_daemon_shell
variable "MySQLNode01_mysql_os_users_daemon_shell" {
  type = "string"
  description = "Default shell configured on Linux server"
  default = "/bin/bash"
}

#Variable : MySQLNode01_mysql_root_password
variable "MySQLNode01_mysql_root_password" {
  type = "string"
  description = "The password for the MySQL root user"
}

#Variable : MySQLNode01_mysql_version
variable "MySQLNode01_mysql_version" {
  type = "string"
  description = "MySQL Version to be installed"
  default = "5.7.17"
}


#########################################################
##### Resource : MySQLNode01
#########################################################

variable "MySQLNode01_domain" {
  type = "string"
  description = "Domain Name of virtual machine"
}

variable "MySQLNode01-os_password" {
  type = "string"
  description = "Operating System Password for the Operating System User to access virtual machine"
}

variable "MySQLNode01_folder" {
  description = "Target vSphere folder for virtual machine"
}

variable "MySQLNode01_datacenter" {
  description = "Target vSphere datacenter for virtual machine creation"
}

variable "MySQLNode01_number_of_vcpu" {
  description = "Number of virtual CPU for the virtual machine, which is required to be a positive Integer"
  default = "2"
}

variable "MySQLNode01_memory" {
  description = "Memory assigned to the virtual machine in megabytes. This value is required to be an increment of 1024"
  default = "2048"
}

variable "MySQLNode01_cluster" {
  description = "Target vSphere cluster to host the virtual machine"
}

variable "MySQLNode01_dns_suffixes" {
  type = "list"
  description = "Name resolution suffixes for the virtual network adapter"
}

variable "MySQLNode01_dns_servers" {
  type = "list"
  description = "DNS servers for the virtual network adapter"
}

variable "MySQLNode01_network_interface_label" {
  description = "vSphere port group or network label for virtual machine's vNIC"
}

variable "MySQLNode01_ipv4_gateway" {
  description = "IPv4 gateway for vNIC configuration"
}

variable "MySQLNode01_ipv4_address" {
  description = "IPv4 address for vNIC configuration"
}

variable "MySQLNode01_ipv4_prefix_length" {
  description = "IPv4 prefix length for vNIC configuration. The value must be a number between 8 and 32"
}

variable "MySQLNode01_root_disk_datastore" {
  description = "Data store or storage cluster name for target virtual machine's disks"
}

variable "MySQLNode01_root_disk_type" {
  type = "string"
  description = "Type of template disk volume"
  default = "eager_zeroed"
}

variable "MySQLNode01_root_disk_controller_type" {
  type = "string"
  description = "Type of template disk controller"
  default = "scsi"
}

variable "MySQLNode01_root_disk_keep_on_remove" {
  type = "string"
  description = "Delete template disk volume when the virtual machine is deleted"
  default = "false"
}

# vsphere vm
resource "vsphere_virtual_machine" "MySQLNode01" {
  name = "${var.MySQLNode01-name}"
  folder = "${var.MySQLNode01_folder}"
  datacenter = "${var.MySQLNode01_datacenter}"
  vcpu = "${var.MySQLNode01_number_of_vcpu}"
  memory = "${var.MySQLNode01_memory}"
  cluster = "${var.MySQLNode01_cluster}"
  dns_suffixes = "${var.MySQLNode01_dns_suffixes}"
  dns_servers = "${var.MySQLNode01_dns_servers}"
  domain = "${var.MySQLNode01_domain}"

  network_interface {
    label = "${var.MySQLNode01_network_interface_label}"
    ipv4_gateway = "${var.MySQLNode01_ipv4_gateway}"
    ipv4_address = "${var.MySQLNode01_ipv4_address}"
    ipv4_prefix_length = "${var.MySQLNode01_ipv4_prefix_length}"
  }

  disk {
    type = "${var.MySQLNode01_root_disk_type}"
    template = "${var.MySQLNode01-image}"
    datastore = "${var.MySQLNode01_root_disk_datastore}"
    keep_on_remove = "${var.MySQLNode01_root_disk_keep_on_remove}"
    controller_type = "${var.MySQLNode01_root_disk_controller_type}"
  }

  # Specify the connection
  connection {
    type = "ssh"
    user = "${var.MySQLNode01-os_admin_user}"
    password = "${var.MySQLNode01-os_password}"
  }

  provisioner "file" {
    destination = "MySQLNode01_add_ssh_key.sh"
    content     = <<EOF
##############################################################
# Licensed Materials - Property of IBM
#
# For use by authorized subscribers only.
#
# Refer to Service Description and SLA available here:
# http://www-03.ibm.com/software/sla/sladb.nsf/sla/saas
#
# D0021ZX IBM Cloud Automation Library, Enterprise Middleware
# © Copyright IBM Corp. 2017
##############################################################
#!/bin/bash

if (( $# != 3 )); then
echo "usage: arg 1 is user, arg 2 is public key, arg3 is CAMC Public Key"
exit -1
fi

userid="$1"
ssh_key="$2"
camc_ssh_key="$3"

user_home=$(eval echo "~$userid")
user_auth_key_file=$user_home/.ssh/authorized_keys
echo "$user_auth_key_file"
if ! [ -f $user_auth_key_file ]; then
echo "$user_auth_key_file does not exist on this system, creating."
mkdir $user_home/.ssh
chmod 600 $user_home/.ssh
echo "" > $user_home/.ssh/authorized_keys
chmod 600 $user_home/.ssh/authorized_keys
else
echo "user_home : $user_home"
fi

if [[ $ssh_key = 'None' ]]; then
echo "skipping user key add, 'None' specified"
else
echo "$user_auth_key_file"
echo "$ssh_key" >> "$user_auth_key_file"
if [ $? -ne 0 ]; then
echo "failed to add to $user_auth_key_file"
exit -1
else
echo "updated $user_auth_key_file"
fi
fi

echo "$camc_ssh_key" >> "$user_auth_key_file"
if [ $? -ne 0 ]; then
echo "failed to add to $user_auth_key_file"
exit -1
else
echo "updated $user_auth_key_file"
fi

EOF
  }

  # Execute the script remotely
  provisioner "remote-exec" {
    inline = [
      "sudo bash -c 'chmod +x MySQLNode01_add_ssh_key.sh'",
      "sudo bash -c './MySQLNode01_add_ssh_key.sh  \"${var.MySQLNode01-os_admin_user}\" \"${var.user_public_ssh_key}\" \"${var.ibm_pm_public_ssh_key}\">> MySQLNode01_add_ssh_key.log 2>&1'"
    ]
  }

}

#########################################################
##### Resource : MySQLNode01_chef_bootstrap_comp
#########################################################

resource "camc_bootstrap" "MySQLNode01_chef_bootstrap_comp" {
  depends_on = ["camc_vaultitem.VaultItem","vsphere_virtual_machine.MySQLNode01"]
  name = "MySQLNode01_chef_bootstrap_comp"
  camc_endpoint = "${var.ibm_pm_service}/v1/bootstrap/chef"
  access_token = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace = true
  data = <<EOT
{
  "os_admin_user": "${var.MySQLNode01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${vsphere_virtual_machine.MySQLNode01.network_interface.0.ipv4_address}",
  "node_name": "${var.MySQLNode01-name}",
  "node_attributes": {
    "ibm_internal": {
      "stack_id": "${random_id.stack_id.hex}",
      "stack_name": "${var.ibm_stack_name}",
      "vault": {
        "item": "secrets",
        "name": "${random_id.stack_id.hex}"
      }
    }
  }
}
EOT
}


#########################################################
##### Resource : MySQLNode01_oracle_mysql_base
#########################################################

resource "camc_softwaredeploy" "MySQLNode01_oracle_mysql_base" {
  depends_on = ["camc_bootstrap.MySQLNode01_chef_bootstrap_comp"]
  name = "MySQLNode01_oracle_mysql_base"
  camc_endpoint = "${var.ibm_pm_service}/v1/software_deployment/chef"
  access_token = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace = true
  data = <<EOT
{
  "os_admin_user": "${var.MySQLNode01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${vsphere_virtual_machine.MySQLNode01.network_interface.0.ipv4_address}",
  "node_name": "${var.MySQLNode01-name}",
  "runlist": "role[oracle_mysql_base]",
  "node_attributes": {
    "ibm": {
      "sw_repo": "${var.ibm_sw_repo}",
      "sw_repo_user": "${var.ibm_sw_repo_user}"
    },
    "ibm_internal": {
      "roles": "[oracle_mysql_base]"
    },
    "mysql": {
      "config": {
        "data_dir": "${var.MySQLNode01_mysql_config_data_dir}",
        "databases": {
          "database_1": {
            "database_name": "${var.MySQLNode01_mysql_config_databases_database_1_database_name}",
            "users": {
              "user_1": {
                "name": "${var.MySQLNode01_mysql_config_databases_database_1_users_user_1_name}"
              },
              "user_2": {
                "name": "${var.MySQLNode01_mysql_config_databases_database_1_users_user_2_name}"
              }
            }
          }
        },
        "log_file": "${var.MySQLNode01_mysql_config_log_file}",
        "port": "${var.MySQLNode01_mysql_config_port}"
      },
      "install_from_repo": "${var.MySQLNode01_mysql_install_from_repo}",
      "os_users": {
        "daemon": {
          "gid": "${var.MySQLNode01_mysql_os_users_daemon_gid}",
          "home": "${var.MySQLNode01_mysql_os_users_daemon_home}",
          "ldap_user": "${var.MySQLNode01_mysql_os_users_daemon_ldap_user}",
          "name": "${var.MySQLNode01_mysql_os_users_daemon_name}",
          "shell": "${var.MySQLNode01_mysql_os_users_daemon_shell}"
        }
      },
      "version": "${var.MySQLNode01_mysql_version}"
    }
  },
  "vault_content": {
    "item": "secrets",
    "values": {
      "ibm": {
        "sw_repo_password": "${var.ibm_sw_repo_password}"
      },
      "mysql": {
        "config": {
          "databases": {
            "database_1": {
              "users": {
                "user_1": {
                  "password": "${var.MySQLNode01_mysql_config_databases_database_1_users_user_1_password}"
                },
                "user_2": {
                  "password": "${var.MySQLNode01_mysql_config_databases_database_1_users_user_2_password}"
                }
              }
            }
          }
        },
        "root_password": "${var.MySQLNode01_mysql_root_password}"
      }
    },
    "vault": "${random_id.stack_id.hex}"
  }
}
EOT
}


#########################################################
##### Resource : VaultItem
#########################################################

resource "camc_vaultitem" "VaultItem" {
  camc_endpoint = "${var.ibm_pm_service}/v1/vault_item/chef"
  access_token = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace = true
  data = <<EOT
{
  "vault_content": {
    "item": "secrets",
    "values": {},
    "vault": "${random_id.stack_id.hex}"
  }
}
EOT
}

output "MySQLNode01_ip" {
  value = "VM IP Address : ${vsphere_virtual_machine.MySQLNode01.network_interface.0.ipv4_address}"
}

output "MySQLNode01_name" {
  value = "${var.MySQLNode01-name}"
}

output "MySQLNode01_roles" {
  value = "oracle_mysql_base"
}

output "stack_id" {
  value = "${random_id.stack_id.hex}"
}

