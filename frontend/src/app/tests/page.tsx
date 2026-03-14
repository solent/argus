import TestsPage, { TestResult } from "./TestsPage";

const ENDPOINT = process.env.NEXT_PUBLIC_BACKEND_ENDPOINT;

type TestResultsResponse = {
  results: Record<string, TestResult>;
  testModels: string[];
  judgeModels: string[];
};

async function getTests(): Promise<{
  tests: TestResult[];
  testModels: string[];
  judgeModels: string[];
}> {
  try {
    const res = await fetch(`${ENDPOINT}/test_results`, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(10000), // ← 10s max
    });

    if (!res.ok) {
      console.error(`[getTests] HTTP ${res.status}: ${res.statusText}`);
      return { tests: [], testModels: [], judgeModels: [] };
    }

    const data = (await res.json()) as TestResultsResponse;

    return {
      tests: Object.values(data.results ?? {}),
      testModels: Array.isArray(data.testModels) ? data.testModels : [],
      judgeModels: Array.isArray(data.judgeModels) ? data.judgeModels : [],
    };
  } catch (e) {
    console.log("[getTests] Error:", e);
    return { tests: [], testModels: [], judgeModels: [] };
  }
}

export default async function Page() {
  const { tests, testModels, judgeModels } = await getTests();
  return (
    <TestsPage
      serverTests={tests}
      testModels={testModels}
      defaultJudgeModels={judgeModels}
    />
  );
}
