coreo_aws_advisor_alert 'daniel' do
  action :define
  service :iam
  description 'Finding Unused Credentials'
  level 'Informational'
  objectives ['users']
  audit_objects ['users.user_name']
  operators ['=~']
  alert_when [//]
end

coreo_aws_advisor_iam 'resulting one' do
  action :advise
  alerts [ 'daniel']
end