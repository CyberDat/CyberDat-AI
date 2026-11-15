# AI Model Bill of Materials — rules 2026-11-14.1 (engine 1.0.0)

Generated from engine.js. Ids, groups and severities were frozen in tests/fixtures/ai-bom/rules.json before the rule code was written.

| Id | Group | Severity | Title | Recommendation |
|---|---|---|---|---|
| AIBOM-LIC-001 | license | medium | Model license missing or unknown | Add the license of the model as an SPDX identifier (for example Apache-2.0) or the name of the license terms. |
| AIBOM-LIC-002 | license | medium | Dataset license missing or unknown | Add the license or the terms under which the dataset was obtained. |
| AIBOM-VER-001 | version | medium | Model version missing | Add the exact version, release date or revision of the model. |
| AIBOM-VER-002 | version | medium | Model version is floating | Use an exact version, snapshot date or commit revision instead of a branch, tag such as “latest”, or range. |
| AIBOM-VER-003 | version | low | Base model version missing or floating | Add the exact version or revision of the base model. |
| AIBOM-WGT-001 | weights | medium | Weights file without a hash | Add a SHA-256 (or stronger) digest of the weights file. |
| AIBOM-WGT-002 | weights | medium | Pickle-based weights format | Prefer safetensors. If a pickle-based file is needed, load it only from a verified source with a checked digest, and in an isolated environment. |
| AIBOM-WGT-003 | weights | low | Weak hash algorithm | Record a SHA-256, SHA-384 or SHA-512 digest. |
| AIBOM-WGT-004 | weights | low | Weights file without a source | Add the download location, registry entry or internal storage path. |
| AIBOM-WGT-005 | weights | low | No weights files listed | List the weights files with format, digest and source. |
| AIBOM-PRV-001 | provenance | medium | Fine-tuned model without a base model | Name the base model and its exact version. |
| AIBOM-DAT-001 | data | medium | Dataset without a source | Add where the dataset comes from: a URL, a catalogue entry or an internal location. |
| AIBOM-DAT-002 | data | medium | Personal data status unknown | State whether the dataset contains personal data: yes or no. |
| AIBOM-DAT-003 | data | low | No datasets listed | List the training and fine-tuning datasets with source, license and personal-data status. |
| AIBOM-DEP-001 | dependencies | medium | Dependency without a version | Add the exact version of each framework and library. |
| AIBOM-DEP-002 | dependencies | low | Dependency version is floating | Pin the exact version that was tested. |
| AIBOM-NET-001 | endpoints | medium | Address uses http:// | Use https:// for this address. |
| AIBOM-SEC-001 | secrets | high | Credentials in an address | Remove the credential from the address, revoke it if it is real, and store it in a secrets manager. |
| AIBOM-SEC-002 | secrets | high | Secret in a field | Remove the value, revoke it if it is real, and refer to the secret by name only (for example “stored in the vault as OCR_API_KEY”). |
| AIBOM-SEC-003 | secrets | medium | Long random-looking value | Check the value. If it is a secret, remove it and revoke it. |
| AIBOM-DOC-001 | documentation | medium | No intended purpose | Describe what the model is used for and by whom. |
| AIBOM-DOC-002 | documentation | medium | No limitations | List known limitations: languages, input types, situations where results are unreliable. |
| AIBOM-DOC-003 | documentation | medium | No quality or safety evaluation | Add the metrics you measured and how the model was checked for safety problems. |
| AIBOM-DOC-004 | documentation | medium | No responsible person or contact | Name the responsible person or team and add a contact (e-mail or URL). |
| AIBOM-DOC-005 | documentation | low | Model type not stated | Choose the model type: own, fine-tuned or external API. |
| AIBOM-DOC-006 | documentation | low | No vendor | Name the vendor or provider of the model. |
| AIBOM-FMT-001 | format | medium | No machine-learning model component | Add the model as a component of type machine-learning-model. |
| AIBOM-FMT-002 | format | low | Structure problems | Correct the fields listed under “Structure”. |
