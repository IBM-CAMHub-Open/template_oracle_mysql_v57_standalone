# =================================================================
# Copyright 2017 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
#	you may not use this file except in compliance with the License.
#	You may obtain a copy of the License at
#
#	  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# =================================================================

# This is a terraform generated template generated from oracle_mysql_v57_standalone

##############################################################
# Keys - CAMC (public/private) & optional User Key (public)
##############################################################
variable "ibm_pm_public_ssh_key_name" {
  description = "Public CAMC SSH key name used to connect to the virtual guest."
}

variable "ibm_pm_private_ssh_key" {
  description = "Private CAMC SSH key (base64 encoded) used to connect to the virtual guest."
}

variable "user_public_ssh_key" {
  type = "string"
  description = "User defined public SSH key used to connect to the virtual machine. The format must be in openSSH."
  default = "None"
}

variable "ibm_stack_id" {
  description = "A unique stack id."
}

##############################################################
# Define the ibm provider
##############################################################
#define the ibm provider
provider "ibm" {
  version = "~> 0.7"
}

provider "camc" {
  version = "~> 0.2"
}

##############################################################
# Reference public key in Devices>Manage>SSH Keys in SL console)
##############################################################
data "ibm_compute_ssh_key" "ibm_pm_public_key" {
  label = "${var.ibm_pm_public_ssh_key_name}"
  most_recent = "true"
}

##############################################################
# Define pattern variables
##############################################################
##### unique stack name #####
variable "ibm_stack_name" {
  description = "A unique stack name."
}


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
  default = "REDHAT_7_64"
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
  description = "Name of the second user which is created and allowed to access the created sample database"
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


##### virtualmachine variables #####
#Variable : MySQLNode01-mgmt-network-public
variable "MySQLNode01-mgmt-network-public" {
  type = "string"
  description = "Expose and use public IP of virtual machine for internal communication"
  default = "true"
}


##### ungrouped variables #####
##### domain name #####
variable "runtime_domain" {
  description = "domain name"
  default = "cam.ibm.com"
}


#########################################################
##### Resource : MySQLNode01
#########################################################


#Parameter : MySQLNode01_datacenter
variable "MySQLNode01_datacenter" {
  type = "string"
  description = "IBMCloud datacenter where infrastructure resources will be deployed"
  default = "dal05"
}


#Parameter : MySQLNode01_private_network_only
variable "MySQLNode01_private_network_only" {
  type = "string"
  description = "Provision the virtual machine with only private IP"
  default = "false"
}


#Parameter : MySQLNode01_number_of_cores
variable "MySQLNode01_number_of_cores" {
  type = "string"
  description = "Number of CPU cores, which is required to be a positive Integer"
  default = "2"
}


#Parameter : MySQLNode01_memory
variable "MySQLNode01_memory" {
  type = "string"
  description = "Amount of Memory (MBs), which is required to be one or more times of 1024"
  default = "4096"
}


#Parameter : MySQLNode01_network_speed
variable "MySQLNode01_network_speed" {
  type = "string"
  description = "Bandwidth of network communication applied to the virtual machine"
  default = "10"
}


#Parameter : MySQLNode01_hourly_billing
variable "MySQLNode01_hourly_billing" {
  type = "string"
  description = "Billing cycle: hourly billed or monthly billed"
  default = "true"
}


#Parameter : MySQLNode01_dedicated_acct_host_only
variable "MySQLNode01_dedicated_acct_host_only" {
  type = "string"
  description = "Shared or dedicated host, where dedicated host usually means higher performance and cost"
  default = "false"
}


#Parameter : MySQLNode01_local_disk
variable "MySQLNode01_local_disk" {
  type = "string"
  description = "User local disk or SAN disk"
  default = "false"
}

variable "MySQLNode01_root_disk_size" {
  type = "string"
  description = "Root Disk Size - MySQLNode01"
  default = "100"
}

resource "ibm_compute_vm_instance" "MySQLNode01" {
  hostname = "${var.MySQLNode01-name}"
  os_reference_code = "${var.MySQLNode01-image}"
  domain = "${var.runtime_domain}"
  datacenter = "${var.MySQLNode01_datacenter}"
  network_speed = "${var.MySQLNode01_network_speed}"
  hourly_billing = "${var.MySQLNode01_hourly_billing}"
  private_network_only = "${var.MySQLNode01_private_network_only}"
  cores = "${var.MySQLNode01_number_of_cores}"
  memory = "${var.MySQLNode01_memory}"
  disks = ["${var.MySQLNode01_root_disk_size}"]
  dedicated_acct_host_only = "${var.MySQLNode01_dedicated_acct_host_only}"
  local_disk = "${var.MySQLNode01_local_disk}"
  ssh_key_ids = ["${data.ibm_compute_ssh_key.ibm_pm_public_key.id}"]
  # Specify the ssh connection
  connection {
    user = "${var.MySQLNode01-os_admin_user}"
    private_key = "${base64decode(var.ibm_pm_private_ssh_key)}"
    bastion_host        = "${var.bastion_host}"
    bastion_user        = "${var.bastion_user}"
    bastion_private_key = "${ length(var.bastion_private_key) > 0 ? base64decode(var.bastion_private_key) : var.bastion_private_key}"
    bastion_port        = "${var.bastion_port}"
    bastion_host_key    = "${var.bastion_host_key}"
    bastion_password    = "${var.bastion_password}"    
  }

  provisioner "file" {
    destination = "MySQLNode01_add_ssh_key.sh"
    content     = <<EOF
# =================================================================
# Copyright 2017 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
#	you may not use this file except in compliance with the License.
#	You may obtain a copy of the License at
#
#	  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#	WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# =================================================================
#!/bin/bash

if (( $# != 2 )); then
    echo "usage: arg 1 is user, arg 2 is public key"
    exit -1
fi

userid=$1
ssh_key=$2

if [[ $ssh_key = 'None' ]]; then
  echo "skipping add, 'None' specified"
  exit 0
fi

user_home=$(eval echo "~$userid")
user_auth_key_file=$user_home/.ssh/authorized_keys
if ! [ -f $user_auth_key_file ]; then
  echo "$user_auth_key_file does not exist on this system"
  exit -1
else
  echo "user_home --> $user_home"
fi

echo $ssh_key >> $user_auth_key_file
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
      "bash -c 'chmod +x MySQLNode01_add_ssh_key.sh'",
      "bash -c './MySQLNode01_add_ssh_key.sh  \"${var.MySQLNode01-os_admin_user}\" \"${var.user_public_ssh_key}\">> MySQLNode01_add_ssh_key.log 2>&1'"
    ]
  }

}

#########################################################
##### Resource : MySQLNode01_chef_bootstrap_comp
#########################################################

resource "camc_bootstrap" "MySQLNode01_chef_bootstrap_comp" {
  depends_on = ["camc_vaultitem.VaultItem","ibm_compute_vm_instance.MySQLNode01"]
  name = "MySQLNode01_chef_bootstrap_comp"
  camc_endpoint = "${var.ibm_pm_service}/v1/bootstrap/chef"
  access_token = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace = true
  data = <<EOT
{
  "os_admin_user": "${var.MySQLNode01-os_admin_user}",
  "stack_id": "${var.ibm_stack_id}",
  "environment_name": "_default",
  "host_ip": "${var.MySQLNode01-mgmt-network-public == "false" ? ibm_compute_vm_instance.MySQLNode01.ipv4_address_private : ibm_compute_vm_instance.MySQLNode01.ipv4_address}",
  "node_name": "${var.MySQLNode01-name}",
  "node_attributes": {
    "ibm_internal": {
      "stack_id": "${var.ibm_stack_id}",
      "stack_name": "${var.ibm_stack_name}",
      "vault": {
        "item": "secrets",
        "name": "${var.ibm_stack_id}"
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
  "stack_id": "${var.ibm_stack_id}",
  "environment_name": "_default",
  "host_ip": "${var.MySQLNode01-mgmt-network-public == "false" ? ibm_compute_vm_instance.MySQLNode01.ipv4_address_private : ibm_compute_vm_instance.MySQLNode01.ipv4_address}",
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
    "vault": "${var.ibm_stack_id}"
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
    "vault": "${var.ibm_stack_id}"
  }
}
EOT
}

output "MySQLNode01_ip" {
  value = "Private : ${ibm_compute_vm_instance.MySQLNode01.ipv4_address_private} & Public : ${ibm_compute_vm_instance.MySQLNode01.ipv4_address}"
}

output "MySQLNode01_name" {
  value = "${var.MySQLNode01-name}"
}

output "MySQLNode01_roles" {
  value = "oracle_mysql_base"
}

output "stack_id" {
  value = "${var.ibm_stack_id}"
}
