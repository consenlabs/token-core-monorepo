import { type ChangeEvent, useMemo, useState } from "react";

import { parsePolicyDocument, stringifyPolicyDocument } from "../../lib/policy";
import defaultRiskPolicyJson from "../../policies/default-risk-policy.json";

const defaultPolicyDocument = parsePolicyDocument(
  JSON.stringify(defaultRiskPolicyJson),
);
const defaultPolicyText = stringifyPolicyDocument(defaultPolicyDocument);

export function usePolicy() {
  const [policyText, setPolicyText] = useState(() => defaultPolicyText);
  const [policyStatus, setPolicyStatus] = useState(
    `已載入 ${defaultPolicyDocument.policies.length} 條預設 policy`,
  );

  const parsedPolicyState = useMemo(() => {
    try {
      return { document: parsePolicyDocument(policyText), error: undefined };
    } catch (error) {
      return {
        document: undefined,
        error:
          error instanceof Error ? error.message : "Policy JSON 解析失敗。",
      };
    }
  }, [policyText]);

  async function handleImportPolicyFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const content = await file.text();
      const document = parsePolicyDocument(content);
      setPolicyText(stringifyPolicyDocument(document));
      setPolicyStatus(`已載入 policy 檔：${file.name}`);
    } catch (error) {
      setPolicyStatus(
        error instanceof Error
          ? `Policy 檔載入失敗：${error.message}`
          : "Policy 檔載入失敗。",
      );
    }
  }

  function handleResetPolicyDocument() {
    setPolicyText(defaultPolicyText);
    setPolicyStatus(
      `已重設為 ${defaultPolicyDocument.policies.length} 條預設 policy`,
    );
  }

  return {
    policyText,
    setPolicyText,
    policyStatus,
    setPolicyStatus,
    parsedPolicyState,
    handleImportPolicyFile,
    handleResetPolicyDocument,
  };
}
