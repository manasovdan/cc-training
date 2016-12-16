coreo_aws_advisor_alert 'daniel' do
  action :define
  service :ec2
  description 'snapshots that are greater than 256 GB that are not encrypted'
  level 'Informational'
  objectives ['snapshots', 'snapshots']
  audit_objects ['snapshot_set.volume_size', 'snapshot_set.encrypted']
  operators ['>', '==']
  alert_when [8, false]
  id_map 'object.snapshot_set.snapshot_id'
end

coreo_aws_advisor_ec2 'another-one' do
  action :advise
  alerts [ 'daniel']
end