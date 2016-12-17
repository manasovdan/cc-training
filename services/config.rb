coreo_aws_advisor_alert 'iam-unused-passwords' do
  action :define
  service :iam
  description 'Finding Unused passwords'
  level 'Informational'
  objectives ['users']
  audit_objects ['users.user_id']
  operators ['=~']
  alert_when [//]
end

coreo_aws_advisor_alert 'iam-unused-access-keys' do
  action :define
  service :iam
  description 'Finding unused access keys'
  level 'Informational'
  objectives ['access_keys']
  audit_objects ['access_key_metadata.access_key_id']
  operators ['=~']
  alert_when [//]
end

coreo_aws_advisor_iam 'resulting one' do
  action :advise
  alerts [ 'iam-unused-passwords']
end

coreo_aws_advisor_iam 'iam-unused-keys' do
  action :advise
  alerts [ 'iam-unused-access-keys']
end
