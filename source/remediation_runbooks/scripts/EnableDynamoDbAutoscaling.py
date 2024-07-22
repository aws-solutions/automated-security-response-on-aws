import time
import boto3


def verify_scalable_target(client, resource_id, scalable_dimension, min_capacity, max_capacity):
    time.sleep(0.5)
    response = client.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=scalable_dimension
    )
    scalable_target = response["ScalableTargets"][0]
    min_capacity_configured = scalable_target["MinCapacity"]
    max_capacity_configured = scalable_target["MaxCapacity"]

    return min_capacity_configured == min_capacity and max_capacity_configured == max_capacity


def verify_scaling_policy(
    client, 
    policy_name, 
    resource_id, 
    scalable_dimension, 
    target_value, 
    scale_out_cooldown, 
    scale_in_cooldown
):
    time.sleep(0.5)
    response = client.describe_scaling_policies(
        PolicyNames=[policy_name],
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=scalable_dimension,
    )
    target_tracking_policy = response["ScalingPolicies"][0]["TargetTrackingScalingPolicyConfiguration"]
    target_value_configured = target_tracking_policy["TargetValue"]
    scale_out_cooldown_configured = target_tracking_policy["ScaleOutCooldown"]
    scale_in_cooldown_configured = target_tracking_policy["ScaleInCooldown"]

    return (
        target_value_configured == target_value
        and scale_out_cooldown_configured == scale_out_cooldown
        and scale_in_cooldown_configured == scale_in_cooldown
    )


def handler(event, context):
    table_name = event["TableName"]
    resource_id = f"table/{table_name}"
    min_read_capacity = event["MinReadCapacity"]
    max_read_capacity = event["MaxReadCapacity"]
    read_target_value = event["TargetReadCapacityUtilization"]
    read_scale_out_cooldown = event["ReadScaleOutCooldown"]
    read_scale_in_cooldown = event["ReadScaleInCooldown"]
    min_write_capacity = event["MinWriteCapacity"]
    max_write_capacity = event["MaxWriteCapacity"]
    write_target_value = event["TargetWriteCapacityUtilization"]
    write_scale_out_cooldown = event["WriteScaleOutCooldown"]
    write_scale_in_cooldown = event["WriteScaleInCooldown"]

    application_autoscaling = boto3.client("application-autoscaling")

    read_target_configured = verify_scalable_target(
        client=application_autoscaling,
        resource_id=resource_id,
        scalable_dimension="dynamodb:table:ReadCapacityUnits",
        min_capacity=min_read_capacity,
        max_capacity=max_read_capacity,
    )

    read_policy_configured = verify_scaling_policy(
        client=application_autoscaling,
        policy_name=f"{table_name}-Policy-Read",
        resource_id=resource_id,
        scalable_dimension="dynamodb:table:ReadCapacityUnits",
        target_value=read_target_value,
        scale_out_cooldown=read_scale_out_cooldown,
        scale_in_cooldown=read_scale_in_cooldown,
    )

    write_target_configured = verify_scalable_target(
        client=application_autoscaling,
        resource_id=resource_id,
        scalable_dimension="dynamodb:table:WriteCapacityUnits",
        min_capacity=min_write_capacity,
        max_capacity=max_write_capacity,
    )

    write_policy_configured = verify_scaling_policy(
        client=application_autoscaling,
        policy_name=f"{table_name}-Policy-Write",
        resource_id=resource_id,
        scalable_dimension="dynamodb:table:WriteCapacityUnits",
        target_value=write_target_value,
        scale_out_cooldown=write_scale_out_cooldown,
        scale_in_cooldown=write_scale_in_cooldown,
    )

    if (
        read_target_configured
        and read_policy_configured
        and write_target_configured
        and write_policy_configured
    ):
        success_message = "Verification of configuration of Application Autoscaling on DynamoDB Table is successful."
        return {"DynamoDbAutoscalingEnabled": success_message}

    raise Exception(f"FAILED TO VERIFY CONFIGURATION OF APPLICATION AUTOSCALING ON DYNAMODB TABLE {table_name}.")