'use client';

import { buttonClassName } from '@anthrion/ui';

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
}

export interface SegmentedProps<T extends string> {
  value: T;
  onChange: (value: T) => void;
  options: SegmentedOption<T>[];
}

/**
 * Small segmented toggle built from design-system buttons (selected = primary,
 * others = secondary). Used for mutually-exclusive choices in the create-scan form.
 */
export function Segmented<T extends string>({ value, onChange, options }: SegmentedProps<T>): React.ReactElement {
  return (
    <div role="group" className="inline-flex flex-wrap gap-2">
      {options.map((option) => {
        const selected = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            aria-pressed={selected}
            onClick={() => onChange(option.value)}
            className={buttonClassName({ variant: selected ? 'primary' : 'secondary', size: 'sm' })}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
