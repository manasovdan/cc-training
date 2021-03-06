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
  json_input '{ "violations": COMPOSITE::coreo_aws_advisor_iam.iam-report-all-users.report}'
  function <<-EOH
        const wayToAllViolations = json_input["violations"]['password_policy']['violations'];
        const keyViolations = Object.keys(wayToAllViolations);

        const userNotUse = [];
        keyViolations.forEach(violationKey => {
            const violationWay = wayToAllViolations[violationKey];
            const wayToViolationObject = violationWay['violating_object'];

            wayToViolationObject.forEach((violationItem, index) => {

                const wayFromItem = violationItem['object'];
                if(!wayFromItem.hasOwnProperty('password_last_used')) {
                    const newUser = {
                        'user_id': wayFromItem.user_id,
                        'user_name': wayFromItem.user_name
                    };
                    userNotUse.push(newUser);
                }
            });
        });
        callback(JSON.stringify(userNotUse));
  EOH
end

coreo_uni_util_notify 'advise-iam-unused-passwords' do
  action :notify
  type 'email'
  allow_empty false
  send_on 'change'
  payload 'rollup report:COMPOSITE::coreo_uni_util_jsrunner.iam-filter-users-with-unused-passwords.return'
  payload_type 'text'
  endpoint ({
      :to => 'daniel@cloudcoreo.com', :subject => 'CloudCoreo iam advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end


#
# coreo_aws_advisor_alert 'iam-all-access-keys' do
#   action :define
#   service :iam
#   description 'Finding all access keys'
#   level 'Informational'
#   id_map 'object.access_key_metadata.access_key_id'
#   objectives ['users', 'access_keys']
#   audit_objects ['', 'access_key_metadata.user_name']
#   call_modifiers [{}, {:user_name => 'users.user_name'}]
#   operators ['', '=~']
#   alert_when ['', //]
# end
#
# coreo_aws_advisor_iam 'iam-all-keys' do
#   action :advise
#   alerts ['iam-all-access-keys']
# end