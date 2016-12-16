coreo_aws_advisor_alert 'daniel' do
  action :define
  service :elb
  description 'What ELBs have healthcheck interval > 2 minutes'
  level 'Informational'
  objectives ['load_balancers']
  audit_objects ['load_balancer_descriptions.health_check.interval']
  operators ['>']
  alert_when [120]
end

coreo_aws_advisor_elb 'another-one' do
  action :advise
  alerts ['daniel']
end