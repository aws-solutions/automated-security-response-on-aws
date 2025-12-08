// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * SSM Parameters for the ASR solution filtering feature
 */
export class ASRParameters {
  /**
   * Prefix for all ASR parameter paths
   */
  public static readonly PATH_PREFIX = '/ASR';

  /**
   * Prefix for all filter-related parameter paths
   */
  public static readonly FILTERS_PREFIX = `${ASRParameters.PATH_PREFIX}/Filters`;

  /**
   * SSM Parameter for Account Filters
   * Comma-separated list of Account IDs to filter on
   */
  public static readonly ACCOUNT_FILTERS = `${ASRParameters.FILTERS_PREFIX}/AccountFilters`;

  /**
   * SSM Parameter for Account Filter Mode
   * Values: "Include", "Exclude", or "Disabled"
   */
  public static readonly ACCOUNT_FILTER_MODE = `${ASRParameters.FILTERS_PREFIX}/AccountFilterMode`;

  /**
   * SSM Parameter for Account Filter Pattern
   * Values: Comma-separated list of 12-digit AWS account IDs. Default value: none. | https://docs.aws.amazon.com/organizations/latest/APIReference/API_Account.html
   */
  public static readonly ACCOUNT_FILTER_PATTERN = /^(none|\d{12}(,\s*\d{12})*)$/;

  /**
   * SSM Parameter for OU Filters
   * Comma-separated list of OU IDs to filter on
   */
  public static readonly OU_FILTERS = `${ASRParameters.FILTERS_PREFIX}/OUFilters`;

  /**
   * SSM Parameter for OU Filter Mode
   * Values: "Include", "Exclude", or "Disabled"
   */
  public static readonly OU_FILTER_MODE = `${ASRParameters.FILTERS_PREFIX}/OUFilterMode`;

  /**
   * SSM Parameter for OU Filter Pattern
   * Values: List of OUs and Organization Root IDs to filter on. Default value: none, provide a comma-separated list of OU IDs (ou-xxxxx-xxxxx) or Organization Root IDs (o-xxxxxxxxx) | https://docs.aws.amazon.com/organizations/latest/APIReference/API_OrganizationalUnit.html and https://docs.aws.amazon.com/organizations/latest/APIReference/API_Organization.html
   */
  public static readonly OU_FILTER_PATTERN =
    /^(none|((o-[a-z0-9]{10,32})|(ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}))(,s*((o-[a-z0-9]{10,32})|(ou-[0-9a-z]{4,32}-[a-z0-9]{8,32})))*)$/; // NOSONAR - Allowed to use for orgs filter

  /**
   * SSM Parameter for Tag Filters
   * Comma-separated list of tag keys to filter on
   */
  public static readonly TAG_FILTERS = `${ASRParameters.FILTERS_PREFIX}/TagFilters`;

  /**
   * SSM Parameter for Tag Filter Mode
   * Values: "Include", "Exclude", or "Disabled"
   */
  public static readonly TAG_FILTER_MODE = `${ASRParameters.FILTERS_PREFIX}/TagFilterMode`;

  /**
   * SSM Parameter for Tag Filter Pattern
   * Values: List of tag keys to filter on. Default value: none, provide a comma-separated list of tag keys | https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_Tag.html
   */
  public static readonly TAG_FILTER_PATTERN =
    /^(none|([a-zA-Z0-9_.:/=+\-@]{1,128})(,\s*([a-zA-Z0-9_.:/=+\-@]{1,128}))*)$/;

  /**
   * Default filter mode - disabled
   */
  public static readonly DEFAULT_FILTER_MODE = 'Disabled';

  /**
   * Filter modes pattern
   */
  public static readonly DEFAULT_FILTER_MODE_PATTERN = /^(Include|Exclude|Disabled)$/;

  /**
   * Default filter value - none
   */
  public static readonly DEFAULT_FILTER_VALUE = 'none';
}

export class CrossAccount {
  public static readonly FIXED_EXTERNAL_ID = 'ASRCrossAccountLogWriter';
}
