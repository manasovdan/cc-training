coreo_aws_advisor_alert 'iam-get-all-users' do
  action :define
  service :iam
  description 'Finding Unused passwords'
  level 'Informational'
  objectives ['users']
  audit_objects ['users.user_id']
  operators ['=~']
  alert_when [//]
end

coreo_aws_advisor_iam 'iam-report-all-users' do
  action :advise
  alerts [ 'iam-get-all-users']
end

coreo_uni_util_jsrunner 'iam-filter-users-with-unused-passwords' do
  action :run
  data_type 'json'
  json_input '{ "violations": COMPOSITE::coreo_aws_advisor_iam.iam-get-all-users.violations}'
  function <<-EOH
    console.log(json_input)

  EOH
end

coreo_aws_advisor_iam 'iam-unused-passwords' do
  action :advise
  alerts [ 'iam-filter-users-with-unused-passwords']
end


#
# coreo_aws_advisor_alert 'iam-unused-access-keys' do
#   action :define
#   service :iam
#   description 'Finding unused access keys'
#   level 'Informational'
#   objectives ['access_keys']
#   audit_objects ['access_key_metadata.user_name']
#   operators ['=~']
#   alert_when [//]
# end
#
# coreo_aws_advisor_iam 'iam-unused-keys' do
#   action :advise
#   alerts [ 'iam-unused-access-keys']
# end
