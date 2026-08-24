// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { useState, useEffect } from 'react';
import Modal from '@cloudscape-design/components/modal';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Button from '@cloudscape-design/components/button';
import Box from '@cloudscape-design/components/box';
import Grid from '@cloudscape-design/components/grid';

import { ResourceFilter, ResourceFilterInput, TagPair } from '@data-models';
import { validateAccountId, validateOrganizationalUnitId, validateArnPattern } from '../../../utils/validation.ts';
import { useTokenListField } from '../../../hooks/useTokenListField.ts';
import { TokenFormField } from '../../../components/TokenFormField.tsx';

export interface ResourceFilterFormProps {
  mode: 'create' | 'edit';
  initialValues?: ResourceFilter;
  onSubmit: (filter: ResourceFilterInput) => void;
  onCancel: () => void;
  isSubmitting: boolean;
}

interface FormErrors {
  name?: string;
  tags?: string;
}

/**
 * Modal form for creating or editing a resource filter.
 * Uses TokenInput for account IDs, OUs, and ARN patterns, and a key-value tag grid.
 */
export default function ResourceFilterForm({
  mode,
  initialValues,
  onSubmit,
  onCancel,
  isSubmitting,
}: Readonly<ResourceFilterFormProps>) {
  const [name, setName] = useState('');
  const [tags, setTags] = useState<TagPair[]>([]);
  const [errors, setErrors] = useState<FormErrors>({});
  const [submitted, setSubmitted] = useState(false);

  const accountIdField = useTokenListField({ validate: validateAccountId });
  const organizationalUnitField = useTokenListField({ validate: validateOrganizationalUnitId });
  const arnPatternField = useTokenListField({ validate: validateArnPattern });

  useEffect(() => {
    if (mode === 'edit' && initialValues) {
      setName(initialValues.name);
      accountIdField.reset(initialValues.accountIds);
      organizationalUnitField.reset(initialValues.organizationalUnits);
      arnPatternField.reset(initialValues.arnPatterns);
      setTags(initialValues.tags);
    } else {
      setName('');
      accountIdField.reset();
      organizationalUnitField.reset();
      arnPatternField.reset();
      setTags([]);
    }
    setErrors({});
    setSubmitted(false);
  }, [mode, initialValues]);

  const validate = (): boolean => {
    const newErrors: FormErrors = {};
    if (!name.trim()) newErrors.name = 'Name is required.';

    const invalidTags = tags.filter((t) => !t.key.trim() || !t.value.trim());
    if (invalidTags.length > 0) newErrors.tags = 'Tag keys and values cannot be empty.';

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = () => {
    setSubmitted(true);
    const hasTokenErrors = accountIdField.error || organizationalUnitField.error || arnPatternField.error;
    const isFormValid = validate();
    if (hasTokenErrors || !isFormValid) return;

    const filter: ResourceFilterInput = {
      name: name.trim(),
      accountIds: accountIdField.tokens.filter(Boolean),
      organizationalUnits: organizationalUnitField.tokens.filter(Boolean),
      tags: tags.filter((t) => t.key.trim() && t.value.trim()),
      arnPatterns: arnPatternField.tokens.filter(Boolean),
    };
    onSubmit(filter);
  };

  useEffect(() => {
    if (submitted) validate();
  }, [name, accountIdField.tokens, organizationalUnitField.tokens, arnPatternField.tokens, tags, submitted]);

  return (
    <Modal
      visible
      onDismiss={onCancel}
      header={mode === 'create' ? 'Create resource filter' : 'Edit resource filter'}
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            <Button variant="link" onClick={onCancel}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleSubmit} loading={isSubmitting} disabled={isSubmitting}>
              {mode === 'create' ? 'Create' : 'Save'}
            </Button>
          </SpaceBetween>
        </Box>
      }
    >
      <Form>
        <SpaceBetween direction="vertical" size="l">
          <FormField label="Filter name" errorText={errors.name}>
            <Input
              value={name}
              onChange={({ detail }) => setName(detail.value)}
              placeholder="e.g., Production Accounts"
              ariaRequired
            />
          </FormField>

          <TokenFormField
            field={accountIdField}
            label="Account IDs"
            description="Enter AWS account IDs (12 digits each)"
            placeholder="Type account ID and press Enter"
            ariaLabel="AWS Account ID input"
            disabled={isSubmitting}
          />

          <TokenFormField
            field={organizationalUnitField}
            label="Organizational Units"
            description="Enter organizational unit IDs (e.g., ou-xxxx-xxxxxxxx)"
            placeholder="Type OU ID and press Enter"
            ariaLabel="Organizational Unit input"
            disabled={isSubmitting}
          />

          <TokenFormField
            field={arnPatternField}
            label="ARN Patterns"
            description="Enter ARN patterns to filter specific resources (e.g., arn:aws:s3:::my-bucket*)"
            placeholder="Type ARN pattern and press Enter"
            ariaLabel="ARN Pattern input"
            disabled={isSubmitting}
          />

          <FormField
            label="Resource tags"
            description="Add key-value pairs to filter resources by tags"
            errorText={errors.tags}
          >
            <SpaceBetween size="s">
              {tags.length === 0 ? (
                <Box textAlign="center" color="text-body-secondary" padding="l">
                  No tags added
                </Box>
              ) : (
                tags.map((tag, index) => (
                  <Grid key={index} gridDefinition={[{ colspan: 5 }, { colspan: 5 }, { colspan: 2 }]}>
                    <FormField label={index === 0 ? 'Key' : undefined}>
                      <Input
                        value={tag.key}
                        onChange={({ detail }) => {
                          const newTags = [...tags];
                          newTags[index] = { ...newTags[index], key: detail.value };
                          setTags(newTags);
                        }}
                        placeholder="Enter tag key"
                        disabled={isSubmitting}
                      />
                    </FormField>
                    <FormField label={index === 0 ? 'Value' : undefined}>
                      <Input
                        value={tag.value}
                        onChange={({ detail }) => {
                          const newTags = [...tags];
                          newTags[index] = { ...newTags[index], value: detail.value };
                          setTags(newTags);
                        }}
                        placeholder="Enter tag value"
                        disabled={isSubmitting}
                      />
                    </FormField>
                    <div style={{ marginTop: index === 0 ? '24px' : '0', display: 'flex', alignItems: 'center' }}>
                      <Button
                        variant="icon"
                        iconName="close"
                        ariaLabel={`Remove tag ${index + 1}`}
                        onClick={() => {
                          const newTags = [...tags];
                          newTags.splice(index, 1);
                          setTags(newTags);
                        }}
                        disabled={isSubmitting}
                      />
                    </div>
                  </Grid>
                ))
              )}
              <Button
                onClick={() => setTags([...tags, { key: '', value: '' }])}
                iconName="add-plus"
                disabled={isSubmitting}
              >
                Add tag
              </Button>
            </SpaceBetween>
          </FormField>
        </SpaceBetween>
      </Form>
    </Modal>
  );
}
