// Front-end of the registry stand: TypeScript, so the auditor has no symbol locator here.
export async function sendDigest(subjectId: string, body: string): Promise<void> {
  await fetch("https://digest.example.invalid/hooks/digest", {
    method: "POST",
    body: JSON.stringify({ subjectId, body }),
  });
}
