import { loadContracts, validateContracts } from "./contracts.mjs";

const errors = validateContracts(await loadContracts());

if (errors.length > 0) {
  for (const error of errors) {
    console.error(error);
  }
  process.exitCode = 1;
} else {
  console.log("Deployment contracts are valid.");
}
