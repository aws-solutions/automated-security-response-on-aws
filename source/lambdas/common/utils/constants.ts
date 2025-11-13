// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * SSM Parameters for the ASR solution filtering feature
 * Local copy for Lambda bundling
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
   * SSM Parameter for Tag Filters
   * Comma-separated list of tag keys to filter on
   */
  public static readonly TAG_FILTERS = `${ASRParameters.FILTERS_PREFIX}/TagFilters`;

  /**
   * SSM Parameter for Tag Filter Mode
   * Values: "Include", "Exclude", or "Disabled"
   */
  public static readonly TAG_FILTER_MODE = `${ASRParameters.FILTERS_PREFIX}/TagFilterMode`;
}
