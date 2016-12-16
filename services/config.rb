coreo_aws_advisor_alert 'daniel' do
  action :define
  service :ec2
  description 'snapshots that are greater than 256 GB that are not encrypted'
  level 'Informational'
  objectives ['describe_instances', 'describe_instances']
  audit_objects ['spot_instance_request_set.launch_specification.block_device_mapping.ebs.volume_size', 'spot_instance_request_set.launch_specification.block_device_mapping.ebs.ecrypted']
  operators ['>', '==']
  alert_when [8, false]
end

coreo_aws_advisor_elb "another-one" do
  action :advise
  alerts [ 'daniel']
end