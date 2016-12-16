coreo_aws_advisor_alert 'daniel' do
  action :define
  service :ec2
  description 'snapshots that are greater than 256 GB that are not encrypted'
  level 'Informational'
  objectives ['instances']
  audit_objects ['spot_instance_request_set.launch_specification.block_device_mapping.ebs.volume_size']
  operators ['>']
  alert_when [8]
end

coreo_aws_advisor_ec2 'another-one' do
  action :advise
  alerts [ 'daniel']
end