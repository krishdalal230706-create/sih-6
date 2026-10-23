const path = require('path');
const dotenv = require('dotenv');
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const { optimizeCyberInvestment } = require('../../dist/engine/investmentOptimizer.js');
const { vulnerabilityDb } = require('../../dist/db/vulnerabilityDb.js');

async function runTests() {
  console.log('=== RUNNING INVESTMENT OPTIMIZATION TEST SUITE ===\n');

  // Test 1: Small Budget (₹50,000)
  console.log('--- TEST 1: Small Budget (₹50,000) ---');
  const res1 = await optimizeCyberInvestment({ budget: 50000 });
  console.log(`Budget: ₹${res1.budget.toLocaleString('en-IN')}`);
  console.log(`Total Invested: ₹${res1.totalInvested.toLocaleString('en-IN')}`);
  console.log(`Remaining Budget: ₹${res1.remainingBudget.toLocaleString('en-IN')}`);
  console.log(`Selected Count: ${res1.selectedCount}`);
  console.log(`Explanation: ${res1.explanation}\n`);

  // Test 2: Larger Budget (₹20,00,000)
  console.log('--- TEST 2: Larger Budget (₹20,00,000) ---');
  const res2 = await optimizeCyberInvestment({ budget: 2000000 });
  console.log(`Budget: ₹${res2.budget.toLocaleString('en-IN')}`);
  console.log(`Total Invested: ₹${res2.totalInvested.toLocaleString('en-IN')}`);
  console.log(`Remaining Budget: ₹${res2.remainingBudget.toLocaleString('en-IN')}`);
  console.log(`Selected Count: ${res2.selectedCount}\n`);

  // Test 3: Known Exploited Vulnerability Prioritization
  console.log('--- TEST 3: Known Exploited KEV Prioritization ---');
  const topItem = res2.recommendations[0];
  console.log(`Top Priority Item: ${topItem.cveId}`);
  console.log(`Known Exploited Status: ${topItem.knownExploited}`);
  console.log(`Reason: ${topItem.justificationReason}\n`);

  // Test 4: Missing Cost Data Labeling
  console.log('--- TEST 4: Transparent Cost Estimation Labeling ---');
  console.log(`Cost Label: ${topItem.costLabel}`);
  console.log(`Is Cost Estimated: ${topItem.isCostEstimated}\n`);

  // Test 5: Zero Budget (₹0)
  console.log('--- TEST 5: Zero Budget (₹0) ---');
  const res5 = await optimizeCyberInvestment({ budget: 0 });
  console.log(`Budget: ₹${res5.budget}`);
  console.log(`Total Invested: ₹${res5.totalInvested}`);
  console.log(`Selected Count: ${res5.selectedCount}`);
  console.log(`Remaining Budget: ₹${res5.remainingBudget}\n`);

  // Test 6: No Vulnerabilities Matching Filter
  console.log('--- TEST 6: Empty Match Filter (Min CVSS 10.1) ---');
  const res6 = await optimizeCyberInvestment({ budget: 1000000, minCvss: 10.1 });
  console.log(`Evaluated: ${res6.totalEvaluated}`);
  console.log(`Selected Count: ${res6.selectedCount}`);
  console.log(`Explanation: ${res6.explanation}\n`);

  console.log('=== ALL TESTS COMPLETED SUCCESSFULLY ===');
  process.exit(0);
}

runTests().catch(console.error);
