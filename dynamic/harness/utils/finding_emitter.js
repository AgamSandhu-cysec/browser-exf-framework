'use strict';

/**
 * @typedef {Object} HarnessFinding
 * @property {string} module
 * @property {'critical'|'high'|'medium'|'low'|'info'} severity
 * @property {string} title
 * @property {string} description
 * @property {string} evidence
 * @property {string} file
 * @property {number|null} line
 * @property {string} remediation
 * @property {string} cwe
 * @property {number} confidence
 * @property {string} [poc_type]
 * @property {string} [poc_payload]
 * @property {string} [poc_description]
 */

/** @type {HarnessFinding[]} */
const _findings = [];

/**
 * Append a harness finding to the in-memory buffer (stdout is written by runner.js).
 * @param {HarnessFinding} finding
 * @returns {void}
 */
function emitFinding(finding) {
  _findings.push(finding);
}

/**
 * @returns {HarnessFinding[]}
 */
function getFindings() {
  return _findings;
}

/**
 * Clear accumulated findings (called at runner start).
 * @returns {void}
 */
function resetFindings() {
  _findings.length = 0;
}

module.exports = { emitFinding, getFindings, resetFindings };
