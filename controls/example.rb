# encoding: utf-8
# copyright: 2018, James Leopold and James Rouse

# Include all other controls from Windows 2016 level 2 Member Server
include_controls 'cis-windows2016' do
  skip_control 'xccdf_org.cisecurity.benchmarks_rule_17.3.1_L1_Ensure_Audit_PNP_Activity_is_set_to_Success'
end

# Custom control to fix 17.3.1
# 'PNP Activity' needs to be changed to 'Plug and Play Events'
control "scs_xccdf_org.cisecurity.benchmarks_rule_17.3.1_L1_Ensure_Audit_PNP_Activity_is_set_to_Success" do
  title "(L1) Ensure 'Audit PNP Activity' is set to 'Success'"
  desc  "
    This policy setting allows you to audit when plug and play detects an external device.

    The recommended state for this setting is: Success.

    **Note:** A Windows 10, Server 2016 or higher OS is required to access and set this value in Group Policy.

    Rationale: Enabling this setting will allow a user to audit events when a device is plugged into a system. This can help alert IT staff if unapproved devices are plugged in.
  "
  impact 1.0
  describe audit_policy do
    its("Plug and Play Events") { should eq "Success" }
  end
end

