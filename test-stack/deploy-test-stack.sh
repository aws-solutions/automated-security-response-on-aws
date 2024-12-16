header "[Pack] Custom Action Lambda"

pushd ./lambda || exit

echo "Cleaning lambda/ directory..."

rm -f controls.json
rm -f cfnresponse.py
rm -f enable_remediation_rules.zip
rm -f reset_remediation_resources.zip

cp ../common/controls.json controls.json
cp ../../source/solution_deploy/source/cfnresponse.py cfnresponse.py
zip enable_remediation_rules.zip enable_remediation_rules.py controls.json cfnresponse.py
zip reset_remediation_resources.zip reset_remediation_resources.py

popd

pushd ./cdk || exit

echo "Synthesizing stacks..."

cdk synth

echo "Deploying stacks..."

cdk deploy TestStack
# Use the following command to customize the parameters for the TestStack
# cdk deploy TestStack --parameters SecurityStandard=YOUR_STANDARD SecurityStandardVersion=YOUR_VERSION RemediationFrequency=1440