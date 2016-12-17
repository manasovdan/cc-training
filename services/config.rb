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

        callback(userNotUse);
  EOH
end




