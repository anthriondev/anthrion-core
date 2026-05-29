import assert from 'node:assert/strict';
import { test } from 'node:test';

import { TokenBudget, TokenBudgetExceededError } from './token-budget';

test('TokenBudget tracks usage & remaining', () => {
  const budget = new TokenBudget(100);
  assert.equal(budget.cap, 100);
  assert.equal(budget.used, 0);
  assert.equal(budget.remaining, 100);
  assert.equal(budget.isExhausted(), false);

  budget.record(30);
  assert.equal(budget.used, 30);
  assert.equal(budget.remaining, 70);

  budget.record(70);
  assert.equal(budget.isExhausted(), true);
  assert.equal(budget.remaining, 0);
});

test('TokenBudget.assertAvailable throws when exhausted (hard stop)', () => {
  const budget = new TokenBudget(50);
  budget.record(50);
  assert.throws(() => budget.assertAvailable(), TokenBudgetExceededError);
});

test('TokenBudget.assertAvailable does not throw when budget remains', () => {
  const budget = new TokenBudget(50);
  budget.record(49);
  assert.doesNotThrow(() => budget.assertAvailable());
});

test('TokenBudget: overshooting the cap is still treated as exhausted', () => {
  const budget = new TokenBudget(100);
  budget.record(120); // single call overshoots the cap
  assert.equal(budget.isExhausted(), true);
  assert.equal(budget.remaining, 0);
  assert.throws(() => budget.assertAvailable(), TokenBudgetExceededError);
});

test('TokenBudget rejects invalid cap & negative tokens', () => {
  assert.throws(() => new TokenBudget(0));
  assert.throws(() => new TokenBudget(-5));
  assert.throws(() => new TokenBudget(1.5));
  const budget = new TokenBudget(10);
  assert.throws(() => budget.record(-1));
});

test('TokenBudgetExceededError carries cap & used', () => {
  const err = new TokenBudgetExceededError(100, 130);
  assert.equal(err.cap, 100);
  assert.equal(err.used, 130);
  assert.match(err.message, /halted/i);
});
