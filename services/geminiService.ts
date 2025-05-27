
import { GoogleGenAI, GenerateContentResponse } from "@google/genai";

const API_KEY = process.env.API_KEY;

if (!API_KEY) {
  console.error("Gemini API_KEY is not set. Please ensure process.env.API_KEY is configured.");
  // Throw an error or handle this case appropriately in a real application.
  // For this example, we'll let it proceed, and formalizeEmail will throw if API_KEY is missing.
}

const ai = new GoogleGenAI({ apiKey: API_KEY || "YOUR_API_KEY_FALLBACK_IF_NEEDED_FOR_DEV_BUT_SHOULD_BE_ENV" }); // Fallback for dev only

const getPromptTemplate = (isReply: boolean, hasEmailContext: boolean): string => {
  if (isReply && hasEmailContext) {
    return `
You are an expert email writing assistant. Your task is to draft a polite, professional, and official reply BODY to the email provided in the 'Original Email Context'.
Use the 'Informal Reply Idea' to understand the user's desired response for the body of the email.
The reply body should be well-structured, with an appropriate salutation (e.g., "Dear [Sender's Name],"), a concise body addressing points from the original email if relevant, and a professional closing (e.g., "Sincerely, [Your Name]").
The Subject line (e.g., "Re: [Original Subject]") and Recipient (To: field) will be handled by the application. You only need to generate the email body text.

Original Email Context:
---
{EMAIL_CONTEXT}
---

Informal Reply Idea (for the email body):
---
{USER_MESSAGE}
---

Return *only* the complete email reply BODY content as a single block of text.
Do not add any introductory or explanatory text such as "Here's the email body:" before or after the email content itself.
Do not include a "Subject:" line in your response.
Example of a reply body:
"Dear [Sender's Name],

Thank you for your email. Regarding your question about X, [provide answer based on informal idea].

I hope this helps.

Sincerely,
[Your Name]"
`;
  }
  // Original prompt for new emails or if context is missing for a reply
  return `
You are an expert email writing assistant. Your task is to convert the following informal message into a polite, professional, and official email.
The email should be well-structured, with a clear subject line (e.g., "Subject: Update on Project Alpha"), appropriate salutation, a concise body, and a professional closing. For the closing, use a generic placeholder like '[Your Name]' if a name is not provided in the informal message.
Maintain the core meaning and intent of the original message. Avoid jargon unless it's clearly part of the original message's context.
Ensure the tone is respectful and formal.

Informal Message:
---
{USER_MESSAGE}
---

Return *only* the complete email content as a single block of text, starting with 'Subject: ...'. Do not add any introductory or explanatory text before or after the email content itself.
`;
};

export async function formalizeEmail(userMessage: string, emailContext?: string): Promise<string> {
  if (!API_KEY) {
    throw new Error("Gemini API key (process.env.API_KEY) is not configured.");
  }

  const isReplyMode = !!emailContext;
  let prompt = getPromptTemplate(isReplyMode, !!emailContext);

  if (isReplyMode && emailContext) {
    prompt = prompt.replace("{EMAIL_CONTEXT}", emailContext).replace("{USER_MESSAGE}", userMessage);
  } else {
    prompt = prompt.replace("{USER_MESSAGE}", userMessage);
  }
  
  let response: GenerateContentResponse | null = null;
  try {
    response = await ai.models.generateContent({
        model: "gemini-2.5-flash-preview-04-17",
        contents: prompt,
        // No thinkingConfig for this task, default thinking (enabled) is fine for quality.
    });
    
    // Check for safety blocks before accessing text
    const candidate = response.candidates?.[0];
    if (candidate?.finishReason === "SAFETY" || response.promptFeedback?.blockReason) {
      const blockReasonDetail = response.promptFeedback?.blockReason || (candidate?.finishReason === "SAFETY" ? "Safety" : "Unknown safety reason");
      console.warn(`Gemini API call blocked due to: ${blockReasonDetail}`);
      throw new Error(`The request was blocked by the AI due to safety settings (${blockReasonDetail}). Please revise your input.`);
    }

    const emailText = response.text;
    if (!emailText || emailText.trim() === "") {
        throw new Error("Received an empty response from the AI.");
    }
    return emailText.trim();

  } catch (error: any) {
    console.error("Error calling Gemini API:", error);
    if (error.message && error.message.includes('API key not valid')) {
        throw new Error("Invalid Gemini API Key. Please check your API key.");
    }
    if (error.message && error.message.toLowerCase().includes('quota')) {
        throw new Error("API quota exceeded. Please check your Gemini API plan and usage.");
    }
    // If it's already a safety error from above, rethrow it.
    if (error.message && error.message.includes("blocked by the AI due to safety settings")) {
        throw error;
    }
    throw new Error(`Failed to generate email via Gemini API: ${error.message || 'Unknown error'}`);
  }
}
