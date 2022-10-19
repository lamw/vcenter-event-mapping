
# NSX 4.0.1.1 (Build 20598726) Events in vCenter Server 8.0 IA (Build 20519528)

**Number of Events:** 258

| EventId | EventDescription |
|------------|-----------|
| com.vmware.nsx.management.nsxt.alarm_management.alarm_service_overloaded | The alarm service is overloaded. |
| com.vmware.nsx.management.nsxt.alarm_management.heavy_volume_of_alarms | Heavy volume of a specific alarm type detected. |
| com.vmware.nsx.management.nsxt.audit_log_health.audit_log_file_update_error | At least one of the monitored log files cannot be written to. |
| com.vmware.nsx.management.nsxt.audit_log_health.remote_logging_server_error | Log messages undeliverable due to incorrect remote logging server configuration. |
| com.vmware.nsx.management.nsxt.capacity.maximum_capacity | A maximum capacity has been breached. |
| com.vmware.nsx.management.nsxt.capacity.maximum_capacity_threshold | A maximum capacity threshold has been breached. |
| com.vmware.nsx.management.nsxt.capacity.minimum_capacity_threshold | A minimum capacity threshold has been breached. |
| com.vmware.nsx.management.nsxt.certificates.ca_bundle_update_recommended | The update for a trusted CA bundle is recommended. |
| com.vmware.nsx.management.nsxt.certificates.ca_bundle_update_suggested | The update for a trusted CA bundle is suggested. |
| com.vmware.nsx.management.nsxt.certificates.certificate_expiration_approaching | A certificate is approaching expiration. |
| com.vmware.nsx.management.nsxt.certificates.certificate_expired | A certificate has expired. |
| com.vmware.nsx.management.nsxt.certificates.certificate_is_about_to_expire | A certificate is about to expire. |
| com.vmware.nsx.management.nsxt.clustering.cluster_degraded | Group member is down. |
| com.vmware.nsx.management.nsxt.clustering.cluster_unavailable | All the group members of the service are down. |
| com.vmware.nsx.management.nsxt.cni_health.hyperbus_manager_connection_down | Hyperbus cannot communicate with the Manager node. |
| com.vmware.nsx.management.nsxt.cni_health.hyperbus_manager_connection_down_on_dpu | Hyperbus on DPU cannot communicate with the Manager node. |
| com.vmware.nsx.management.nsxt.communication.control_channel_to_manager_node_down | Transport node's control plane connection to the Manager node is down. |
| com.vmware.nsx.management.nsxt.communication.control_channel_to_manager_node_down_too_long | Transport node's control plane connection to the Manager node is down for long. |
| com.vmware.nsx.management.nsxt.communication.control_channel_to_transport_node_down | Controller service to Transport node's connection is down. |
| com.vmware.nsx.management.nsxt.communication.control_channel_to_transport_node_down_long | Controller service to Transport node's connection is down for too long. |
| com.vmware.nsx.management.nsxt.communication.limited_reachability_on_dpu | The given collector can not be reached via vmknic(s) on given DVS on DPU. |
| com.vmware.nsx.management.nsxt.communication.management_channel_to_manager_node_down | Management channel to Manager node is down. |
| com.vmware.nsx.management.nsxt.communication.management_channel_to_manager_node_down_long | Management channel to Manager node is down for too long. |
| com.vmware.nsx.management.nsxt.communication.management_channel_to_transport_node_down | Management channel to Transport node is down. |
| com.vmware.nsx.management.nsxt.communication.management_channel_to_transport_node_down_long | Management channel to Transport node is down for too long. |
| com.vmware.nsx.management.nsxt.communication.manager_cluster_latency_high | The average network latency between Manager nodes is high. |
| com.vmware.nsx.management.nsxt.communication.manager_control_channel_down | Manager to controller channel is down. |
| com.vmware.nsx.management.nsxt.communication.manager_fqdn_lookup_failure | DNS lookup failed for Manager node's FQDN. |
| com.vmware.nsx.management.nsxt.communication.manager_fqdn_reverse_lookup_failure | Reverse DNS lookup failed for Manager node's IP address. |
| com.vmware.nsx.management.nsxt.communication.network_latency_high | Management to Transport node network latency is high. |
| com.vmware.nsx.management.nsxt.communication.unreachable_collector_on_dpu | The given collector can not be reached via existing vmknic(s) on DPU at all. |
| com.vmware.nsx.management.nsxt.dhcp.pool_lease_allocation_failed | IP addresses in an IP Pool have been exhausted. |
| com.vmware.nsx.management.nsxt.dhcp.pool_overloaded | An IP Pool is overloaded. |
| com.vmware.nsx.management.nsxt.distributed_firewall.dfw_cpu_usage_very_high | DFW CPU usage is very high. |
| com.vmware.nsx.management.nsxt.distributed_firewall.dfw_cpu_usage_very_high_on_dpu | DFW CPU usage is very high on dpu. |
| com.vmware.nsx.management.nsxt.distributed_firewall.dfw_memory_usage_very_high | DFW Memory usage is very high. |
| com.vmware.nsx.management.nsxt.distributed_firewall.dfw_memory_usage_very_high_on_dpu | DFW Memory usage is very high on DPU. |
| com.vmware.nsx.management.nsxt.distributed_firewall.dfw_rules_limit_per_host_approaching | DFW rules limit per host is approaching the maximum limit. |
| com.vmware.nsx.management.nsxt.distributed_firewall.dfw_rules_limit_per_host_exceeded | DFW rules limit per host is about to exceed the maximum limit. |
| com.vmware.nsx.management.nsxt.distributed_firewall.dfw_rules_limit_per_vnic_approaching | DFW rules limit per vNIC is approaching the maximum limit. |
| com.vmware.nsx.management.nsxt.distributed_firewall.dfw_rules_limit_per_vnic_exceeded | DFW rules limit per vNIC is about to exceed the maximum limit. |
| com.vmware.nsx.management.nsxt.distributed_firewall.dfw_session_count_high | DFW session count is high. |
| com.vmware.nsx.management.nsxt.distributed_firewall.dfw_vmotion_failure | DFW vMotion failed, port disconnected. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.idps_engine_bypassed_traffic_cpu_oversubscribed | Distributed IDPS Engine Bypassed Traffic due to CPU Oversubscription. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.idps_engine_bypassed_traffic_network_oversubscribed | Distributed IDPS Engine Bypassed Traffic due to Network Oversubscription. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.idps_engine_cpu_oversubscription_high | CPU utilization for distributed IDPS engine is high. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.idps_engine_cpu_oversubscription_very_high | CPU utilization for distributed IDPS engine is very high. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.idps_engine_dropped_traffic_cpu_oversubscribed | Distributed IDPS Engine Dropped Traffic due to CPU Oversubscription. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.idps_engine_dropped_traffic_network_oversubscribed | Distributed IDPS Engine Dropped Traffic due to Network Oversubscription. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.idps_engine_network_oversubscription_high | Network utilization for distributed IDPS engine is high. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.idps_engine_network_oversubscription_very_high | Network utilization for distributed IDPS engine is very high. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.max_events_reached | Max number of intrusion events reached. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.nsx_idps_engine_down | NSX IDPS is enabled via NSX Policy and IDPS rules are configured, but NSX-IDPS engine is down. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.nsx_idps_engine_down_on_dpu | NSX IDPS is enabled via NSX Policy and IDPS rules are configured, but NSX-IDPS engine is down on DPU. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.nsx_idps_engine_memory_usage_high | NSX-IDPS engine memory usage reaches 75% or above. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.nsx_idps_engine_memory_usage_high_on_dpu | NSX-IDPS engine memory usage reaches 75% or above on DPU. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.nsx_idps_engine_memory_usage_medium_high | NSX-IDPS Engine memory usage reaches 85% or above. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.nsx_idps_engine_memory_usage_medium_high_on_dpu | NSX-IDPS Engine memory usage reaches 85% or above on DPU. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.nsx_idps_engine_memory_usage_very_high | NSX-IDPS engine memory usage reaches 95% or above. |
| com.vmware.nsx.management.nsxt.distributed_ids_ips.nsx_idps_engine_memory_usage_very_high_on_dpu | NSX-IDPS engine memory usage reaches 95% or above on DPU. |
| com.vmware.nsx.management.nsxt.dns.forwarder_down | A DNS forwarder is down. |
| com.vmware.nsx.management.nsxt.dns.forwarder_upstream_server_timeout | One DNS forwarder upstream server has timed out. |
| com.vmware.nsx.management.nsxt.edge_cluster.edge_cluster_member_relocate_failure | Edge cluster member relocate failure alarm |
| com.vmware.nsx.management.nsxt.edge_health.datapath_thread_deadlocked | Edge node's datapath thread is in deadlock condition. |
| com.vmware.nsx.management.nsxt.edge_health.edge_cpu_usage_high | Edge node CPU usage is high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_cpu_usage_very_high | Edge node CPU usage is very high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_datapath_configuration_failure | Edge node datapath configuration failed. |
| com.vmware.nsx.management.nsxt.edge_health.edge_datapath_cpu_high | Edge node datapath CPU usage is high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_datapath_cpu_very_high | Edge node datapath CPU usage is very high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_datapath_cryptodrv_down | Edge node crypto driver is down. |
| com.vmware.nsx.management.nsxt.edge_health.edge_datapath_mempool_high | Edge node datapath mempool is high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_datapath_nic_throughput_high | Edge node datapath NIC throughput is high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_datapath_nic_throughput_very_high | Edge node datapath NIC throughput is very high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_disk_usage_high | Edge node disk usage is high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_disk_usage_very_high | Edge node disk usage is very high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_global_arp_table_usage_high | Edge node global ARP table usage is high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_memory_usage_high | Edge node memory usage is high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_memory_usage_very_high | Edge node memory usage is very high. |
| com.vmware.nsx.management.nsxt.edge_health.edge_nic_link_status_down | Edge node NIC link is down. |
| com.vmware.nsx.management.nsxt.edge_health.edge_nic_out_of_receive_buffer | Edge node NIC is out of RX ring buffers temporarily. |
| com.vmware.nsx.management.nsxt.edge_health.edge_nic_out_of_transmit_buffer | Edge node NIC is out of TX ring buffers temporarily. |
| com.vmware.nsx.management.nsxt.edge_health.failure_domain_down | All members of failure domain are down. |
| com.vmware.nsx.management.nsxt.edge_health.storage_error | Edge node disk is read-only. |
| com.vmware.nsx.management.nsxt.edge.edge_hardware_version_mismatch | Edge node has hardware version mismatch. |
| com.vmware.nsx.management.nsxt.edge.edge_node_settings_and_vsphere_settings_are_changed | Edge node settings and vSphere settings are changed. |
| com.vmware.nsx.management.nsxt.edge.edge_node_settings_mismatch | Edge node settings mismatch. |
| com.vmware.nsx.management.nsxt.edge.edge_vm_not_present_in_both_nsx_inventory_and_vcenter | Auto Edge VM is not present in both NSX inventory and in vCenter. |
| com.vmware.nsx.management.nsxt.edge.edge_vm_present_in_nsx_inventory_not_present_in_vcenter | Auto Edge VM is present in NSX inventory but not present in vCenter. |
| com.vmware.nsx.management.nsxt.edge.edge_vm_vsphere_settings_mismatch | Edge VM vSphere settings mismatch. |
| com.vmware.nsx.management.nsxt.edge.edge_vsphere_location_mismatch | Edge vSphere Location Mismatch. |
| com.vmware.nsx.management.nsxt.edge.failed_to_delete_the_old_vm_in_vcenter_during_redeploy | Power off and delete operation failed for old Edge VM in vCenter during Redeploy. |
| com.vmware.nsx.management.nsxt.endpoint_protection.eam_status_down | ESX Agent Manager (EAM) service on a compute manager is down. |
| com.vmware.nsx.management.nsxt.endpoint_protection.partner_channel_down | Host module and Partner SVM connection is down. |
| com.vmware.nsx.management.nsxt.federation.gm_to_gm_latency_warning | Latency between Global Managers is higher than expected for more than 2 minutes |
| com.vmware.nsx.management.nsxt.federation.gm_to_gm_split_brain | Multiple Global Manager nodes are active at the same time. |
| com.vmware.nsx.management.nsxt.federation.gm_to_gm_synchronization_error | Active Global Manager to Standby Global Manager cannot synchronize for more than 5 minutes |
| com.vmware.nsx.management.nsxt.federation.gm_to_gm_synchronization_warning | Active Global Manager to Standby Global Manager cannot synchronize |
| com.vmware.nsx.management.nsxt.federation.gm_to_lm_latency_warning | Latency between Global Manager and Local Manager is higher than expected for more than 2 minutes. |
| com.vmware.nsx.management.nsxt.federation.gm_to_lm_synchronization_error | Data synchronization between Global Manager (GM) and Local Manager (LM) failed for an extended period. |
| com.vmware.nsx.management.nsxt.federation.gm_to_lm_synchronization_warning | Data synchronization between Global Manager (GM) and Local Manager (LM) failed. |
| com.vmware.nsx.management.nsxt.federation.lm_restore_while_config_import_in_progress | Local Manager is restored while config import is in progress on Global Manager. |
| com.vmware.nsx.management.nsxt.federation.lm_to_lm_synchronization_error | Synchronization between remote locations failed for more than 5 minutes. |
| com.vmware.nsx.management.nsxt.federation.lm_to_lm_synchronization_warning | Synchronization between remote locations failed. |
| com.vmware.nsx.management.nsxt.federation.queue_occupancy_threshold_exceeded | Queue occupancy size threshold exceeded warning. |
| com.vmware.nsx.management.nsxt.federation.rtep_bgp_down | RTEP BGP neighbor down. |
| com.vmware.nsx.management.nsxt.federation.rtep_connectivity_lost | RTEP location connectivity lost. |
| com.vmware.nsx.management.nsxt.gateway_firewall.icmp_flow_count_exceeded | The gateway firewall flow table for ICMP traffic has exceeded the set threshold. New flows will be dropped by Gateway firewall when usage reaches the maximum limit. |
| com.vmware.nsx.management.nsxt.gateway_firewall.icmp_flow_count_high | The gateway firewall flow table usage for ICMP traffic is high. New flows will be dropped by Gateway firewall when usage reaches the maximum limit. |
| com.vmware.nsx.management.nsxt.gateway_firewall.ip_flow_count_exceeded | The gateway firewall flow table for IP traffic has exceeded the set threshold. New flows will be dropped by Gateway firewall when usage reaches the maximum limit. |
| com.vmware.nsx.management.nsxt.gateway_firewall.ip_flow_count_high | The gateway firewall flow table usage for IP traffic is high. New flows will be dropped by Gateway firewall when usage reaches the maximum limit. |
| com.vmware.nsx.management.nsxt.gateway_firewall.tcp_half_open_flow_count_exceeded | The gateway firewall flow table for TCP half-open traffic has exceeded the set threshold. New flows will be dropped by Gateway firewall when usage reaches the maximum limit. |
| com.vmware.nsx.management.nsxt.gateway_firewall.tcp_half_open_flow_count_high | The gateway firewall flow table usage for TCP half-open traffic is high. New flows will be dropped by Gateway firewall when usage reaches the maximum limit. |
| com.vmware.nsx.management.nsxt.gateway_firewall.udp_flow_count_exceeded | The gateway firewall flow table for UDP traffic has exceeded the set threshold. New flows will be dropped by Gateway firewall when usage reaches the maximum limit. |
| com.vmware.nsx.management.nsxt.gateway_firewall.udp_flow_count_high | The gateway firewall flow table usage for  UDP traffic is high. New flows will be dropped by Gateway firewall when usage reaches the maximum limit. |
| com.vmware.nsx.management.nsxt.high_availability.tier0_gateway_failover | A tier0 gateway has failed over. |
| com.vmware.nsx.management.nsxt.high_availability.tier1_gateway_failover | A tier1 gateway has failed over. |
| com.vmware.nsx.management.nsxt.identity_firewall.connectivity_to_ldap_server_lost | Connectivity to LDAP server is lost. |
| com.vmware.nsx.management.nsxt.identity_firewall.error_in_delta_sync | Errors occurred while performing delta sync. |
| com.vmware.nsx.management.nsxt.infrastructure_communication.edge_tunnels_down | An Edge node's tunnel status is down. |
| com.vmware.nsx.management.nsxt.infrastructure_service.application_crashed | Application has crashed and generated a core dump. |
| com.vmware.nsx.management.nsxt.infrastructure_service.edge_service_status_changed | Edge service status has changed. |
| com.vmware.nsx.management.nsxt.infrastructure_service.service_status_unknown | Service's status is abnormal. |
| com.vmware.nsx.management.nsxt.infrastructure_service.service_status_unknown_on_dpu | Service's status on DPU is abnormal. |
| com.vmware.nsx.management.nsxt.ipam.ip_block_usage_very_high | IP block usage is very high. |
| com.vmware.nsx.management.nsxt.ipam.ip_pool_usage_very_high | IP pool usage is very high. |
| com.vmware.nsx.management.nsxt.licenses.license_expired | A license has expired. |
| com.vmware.nsx.management.nsxt.licenses.license_is_about_to_expire | A license is about to expired. |
| com.vmware.nsx.management.nsxt.load_balancer.dlb_status_down | Distributed load balancer service is down. |
| com.vmware.nsx.management.nsxt.load_balancer.lb_cpu_very_high | Load balancer CPU usage is very high. |
| com.vmware.nsx.management.nsxt.load_balancer.lb_edge_capacity_in_use_high | Load balancer usage is high. |
| com.vmware.nsx.management.nsxt.load_balancer.lb_pool_member_capacity_in_use_very_high | Load balancer pool member usage is very high. |
| com.vmware.nsx.management.nsxt.load_balancer.lb_status_degraded | Load balancer service is degraded. |
| com.vmware.nsx.management.nsxt.load_balancer.lb_status_down | Centralized load balancer service is down. |
| com.vmware.nsx.management.nsxt.load_balancer.load_balancing_configuration_not_realized_due_to_lack_of_memory | Load balancer configuration is not realized due to high memory usage on Edge node. |
| com.vmware.nsx.management.nsxt.load_balancer.pool_status_down | Load balancer pool is down. |
| com.vmware.nsx.management.nsxt.load_balancer.virtual_server_status_down | Load balancer virtual service is down. |
| com.vmware.nsx.management.nsxt.malware_prevention_health.analyst_api_service_unreachable | Service status is degraded. |
| com.vmware.nsx.management.nsxt.malware_prevention_health.database_unreachable | Service status is degraded. |
| com.vmware.nsx.management.nsxt.malware_prevention_health.file_extraction_service_unreachable | Service status is degraded. |
| com.vmware.nsx.management.nsxt.malware_prevention_health.ntics_reputation_service_unreachable | Service status is degraded. |
| com.vmware.nsx.management.nsxt.malware_prevention_health.service_status_down | Service status is down. |
| com.vmware.nsx.management.nsxt.manager_health.duplicate_ip_address | Manager node's IP address is in use by another device. |
| com.vmware.nsx.management.nsxt.manager_health.manager_config_disk_usage_high | Manager node config disk usage is high. |
| com.vmware.nsx.management.nsxt.manager_health.manager_config_disk_usage_very_high | Manager node config disk usage is very high. |
| com.vmware.nsx.management.nsxt.manager_health.manager_cpu_usage_high | Manager node CPU usage is high. |
| com.vmware.nsx.management.nsxt.manager_health.manager_cpu_usage_very_high | Manager node CPU usage is very high. |
| com.vmware.nsx.management.nsxt.manager_health.manager_disk_usage_high | Manager node disk usage is high. |
| com.vmware.nsx.management.nsxt.manager_health.manager_disk_usage_very_high | Manager node disk usage is very high. |
| com.vmware.nsx.management.nsxt.manager_health.manager_memory_usage_high | Manager node memory usage is high. |
| com.vmware.nsx.management.nsxt.manager_health.manager_memory_usage_very_high | Manager node memory usage is very high. |
| com.vmware.nsx.management.nsxt.manager_health.operations_db_disk_usage_high | Manager node nonconfig disk usage is high. |
| com.vmware.nsx.management.nsxt.manager_health.operations_db_disk_usage_very_high | Manager node nonconfig disk usage is very high. |
| com.vmware.nsx.management.nsxt.manager_health.storage_error | Manager node disk is read-only. |
| com.vmware.nsx.management.nsxt.mtu_check.global_router_mtu_too_big | The global router MTU configuration is bigger than the MTU of overlay Transport Zone. |
| com.vmware.nsx.management.nsxt.mtu_check.mtu_mismatch_within_transport_zone | MTU configuration mismatch between Transport Nodes attached to the same Transport Zone. |
| com.vmware.nsx.management.nsxt.nat.snat_port_usage_on_gateway_is_high | SNAT port usage on the Gateway is high. |
| com.vmware.nsx.management.nsxt.ncp_health.ncp_plugin_down | Manager Node has detected the NCP is down or unhealthy. |
| com.vmware.nsx.management.nsxt.node_agents_health.node_agents_down | The agents running inside the Node VM appear to be down. |
| com.vmware.nsx.management.nsxt.node_agents_health.node_agents_down_on_dpu | The agents running inside the Node VM appear to be down on DPU. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_communication.delay_detected_in_messaging_overflow | Slow data processing detected in messaging topic Over Flow. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_communication.delay_detected_in_messaging_rawflow | Slow data processing detected in messaging topic Raw Flow. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_communication.manager_disconnected | The NSX Application Platform cluster is disconnected from the NSX management cluster. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_communication.tn_flow_exp_disconnected | A Transport node is disconnected from its NSX Application Platform cluster's messaging broker. Data collection is affected. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_communication.tn_flow_exp_disconnected_on_dpu | A Transport node is disconnected from its Intelligence node's messaging broker. Data collection is affected on DPU. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.analytics_cpu_usage_high | Analytics service CPU usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.analytics_cpu_usage_very_high | Analytics service CPU usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.analytics_disk_usage_high | Analytics service disk usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.analytics_disk_usage_very_high | Analytics service disk usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.analytics_memory_usage_high | Analytics service memory usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.analytics_memory_usage_very_high | Analytics service memory usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.cluster_cpu_usage_high | NSX Application Platform cluster CPU usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.cluster_cpu_usage_very_high | NSX Application Platform cluster CPU usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.cluster_disk_usage_high | NSX Application Platform cluster disk usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.cluster_disk_usage_very_high | NSX Application Platform cluster disk usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.cluster_memory_usage_high | NSX Application Platform cluster memory usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.cluster_memory_usage_very_high | NSX Application Platform cluster memory usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.configuration_db_cpu_usage_high | Configuration Database service CPU usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.configuration_db_cpu_usage_very_high | Configuration Database service CPU usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.configuration_db_disk_usage_high | Configuration Database service disk usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.configuration_db_disk_usage_very_high | Configuration Database service disk usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.configuration_db_memory_usage_high | Configuration Database service memory usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.configuration_db_memory_usage_very_high | Configuration Database service memory usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.datastore_cpu_usage_high | Data Storage service CPU usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.datastore_cpu_usage_very_high | Data Storage service CPU usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.datastore_disk_usage_high | Data Storage service disk usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.datastore_disk_usage_very_high | Data Storage service disk usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.datastore_memory_usage_high | Data Storage service memory usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.datastore_memory_usage_very_high | Data Storage service memory usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.messaging_cpu_usage_high | Messaging service CPU usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.messaging_cpu_usage_very_high | Messaging service CPU usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.messaging_disk_usage_high | Messaging service disk usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.messaging_disk_usage_very_high | Messaging service disk usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.messaging_memory_usage_high | Messaging service memory usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.messaging_memory_usage_very_high | Messaging service memory usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.metrics_cpu_usage_high | Metrics service CPU usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.metrics_cpu_usage_very_high | Metrics service CPU usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.metrics_disk_usage_high | Metrics service disk usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.metrics_disk_usage_very_high | Metrics service disk usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.metrics_memory_usage_high | Metrics service memory usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.metrics_memory_usage_very_high | Metrics service memory usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.napp_status_degraded | NSX Application Platform cluster overall status is degraded. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.napp_status_down | NSX Application Platform cluster overall status is down. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.node_cpu_usage_high | NSX Application Platform node CPU usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.node_cpu_usage_very_high | NSX Application Platform node CPU usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.node_disk_usage_high | NSX Application Platform node disk usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.node_disk_usage_very_high | NSX Application Platform node disk usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.node_memory_usage_high | NSX Application Platform node memory usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.node_memory_usage_very_high | NSX Application Platform node memory usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.node_status_degraded | NSX Application Platform node status is degraded. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.node_status_down | NSX Application Platform node status is down. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.platform_cpu_usage_high | Platform Services service CPU usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.platform_cpu_usage_very_high | Platform Services service CPU usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.platform_disk_usage_high | Platform Services service disk usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.platform_disk_usage_very_high | Platform Services service disk usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.platform_memory_usage_high | Platform Services service memory usage is high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.platform_memory_usage_very_high | Platform Services service memory usage is very high. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.service_status_degraded | Service status is degraded. |
| com.vmware.nsx.management.nsxt.nsx_application_platform_health.service_status_down | Service status is down. |
| com.vmware.nsx.management.nsxt.password_management.password_expiration_approaching | User password is approaching expiration. |
| com.vmware.nsx.management.nsxt.password_management.password_expired | User password has expired. |
| com.vmware.nsx.management.nsxt.password_management.password_is_about_to_expire | User password is about to expire. |
| com.vmware.nsx.management.nsxt.physical_server.physical_server_install_failed | Physical Server (BMS) installation failed. |
| com.vmware.nsx.management.nsxt.physical_server.physical_server_uninstall_failed | Physical Server (BMS) uninstallation failed. |
| com.vmware.nsx.management.nsxt.physical_server.physical_server_upgrade_failed | Physical Server (BMS) upgrade failed. |
| com.vmware.nsx.management.nsxt.routing.bfd_down_on_external_interface | BFD session is down. |
| com.vmware.nsx.management.nsxt.routing.bgp_down | BGP neighbor down. |
| com.vmware.nsx.management.nsxt.routing.maximum_ipv4_prefixes_from_bgp_neighbor_approaching | Maximum IPv4 Prefixes received from BGP neighbor is approaching. |
| com.vmware.nsx.management.nsxt.routing.maximum_ipv4_prefixes_from_bgp_neighbor_exceeded | Maximum IPv4 Prefixes received from BGP neighbor has exceeded. |
| com.vmware.nsx.management.nsxt.routing.maximum_ipv4_route_limit_approaching | Maximum IPv4 Routes limit is approaching on Edge node. |
| com.vmware.nsx.management.nsxt.routing.maximum_ipv4_route_limit_exceeded | Maximum IPv4 Routes limit has exceeded on Edge node. |
| com.vmware.nsx.management.nsxt.routing.maximum_ipv6_prefixes_from_bgp_neighbor_approaching | Maximum IPv6 Prefixes received from BGP neighbor is approaching. |
| com.vmware.nsx.management.nsxt.routing.maximum_ipv6_prefixes_from_bgp_neighbor_exceeded | Maximum IPv6 Prefixes received from BGP neighbor has exceeded. |
| com.vmware.nsx.management.nsxt.routing.maximum_ipv6_route_limit_approaching | Maximum IPv6 Routes limit is approaching on Edge node. |
| com.vmware.nsx.management.nsxt.routing.maximum_ipv6_route_limit_exceeded | Maximum IPv6 Routes limit has exceeded on Edge node. |
| com.vmware.nsx.management.nsxt.routing.ospf_neighbor_went_down | OSPF neighbor moved from full to another state. |
| com.vmware.nsx.management.nsxt.routing.proxy_arp_not_configured_for_service_ip | Proxy ARP is not configured for Service IP. |
| com.vmware.nsx.management.nsxt.routing.routing_down | All BGP/BFD sessions are down. |
| com.vmware.nsx.management.nsxt.routing.static_routing_removed | Static route removed. |
| com.vmware.nsx.management.nsxt.service_insertion.new_host_added | New Host added in cluster. |
| com.vmware.nsx.management.nsxt.service_insertion.service_chain_path_down | Service chain path down. |
| com.vmware.nsx.management.nsxt.service_insertion.service_deployment_failed | Service deployment failed. |
| com.vmware.nsx.management.nsxt.service_insertion.service_deployment_succeeded | Service deployment succeeded. |
| com.vmware.nsx.management.nsxt.service_insertion.service_insertion_infra_status_down | Service insertion infrastructure status down and not enabled on host. |
| com.vmware.nsx.management.nsxt.service_insertion.service_undeployment_failed | Service deployment deletion failed. |
| com.vmware.nsx.management.nsxt.service_insertion.service_undeployment_succeeded | Service deployment deletion succeeded. |
| com.vmware.nsx.management.nsxt.service_insertion.svm_health_status_down | SVM is not working in service. |
| com.vmware.nsx.management.nsxt.service_insertion.svm_health_status_up | SVM is working in service. |
| com.vmware.nsx.management.nsxt.service_insertion.svm_liveness_state_down | SVM liveness state down. |
| com.vmware.nsx.management.nsxt.transport_node_health.lag_member_down | LACP reporting member down. |
| com.vmware.nsx.management.nsxt.transport_node_health.lag_member_down_on_dpu | LACP on DPU reporting member down. |
| com.vmware.nsx.management.nsxt.transport_node_health.transport_node_uplink_down | Uplink is going down. |
| com.vmware.nsx.management.nsxt.transport_node_health.transport_node_uplink_down_on_dpu | Uplink on DPU is going down. |
| com.vmware.nsx.management.nsxt.vpn.ipsec_policy_based_session_down | Policy based IPsec VPN session is down. |
| com.vmware.nsx.management.nsxt.vpn.ipsec_policy_based_tunnel_down | policy Based IPsec VPN tunnels are down. |
| com.vmware.nsx.management.nsxt.vpn.ipsec_route_based_session_down | Route based IPsec VPN session is down. |
| com.vmware.nsx.management.nsxt.vpn.ipsec_route_based_tunnel_down | Route based IPsec VPN tunnel is down. |
| com.vmware.nsx.management.nsxt.vpn.ipsec_service_down | IPsec service is down. |
| com.vmware.nsx.management.nsxt.vpn.l2vpn_session_down | L2VPN session is down. |

