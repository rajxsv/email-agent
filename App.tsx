import React, { useState, useCallback, useEffect, useRef } from 'react';
import { formalizeEmail } from './services/geminiService'; // Assuming this service exists
import LoadingSpinner from './components/LoadingSpinner';    // Assuming this component exists
import { jwtDecode } from 'jwt-decode';

// Extend Window interface to include google and gapi objects
declare global {
  interface Window {
    google: any;
    gapi: any;
  }
}

interface DecodedCredential {
  email: string;
  name: string;
  picture?: string;
  sub: string; // User ID
}

interface GmailEmail {
  id: string;
  threadId: string;
  subject: string;
  snippet: string;
  from: string;
  body: string; // Plain text body
  date: string;
}

interface AccessTokenResponse {
  access_token: string;
  expires_in: number;
  scope: string;
  token_type: string;
  error?: string;
  error_description?: string;
}

const CopyIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className || "w-5 h-5"}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 01-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 011.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.06 9.06 0 00-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 4.625v2.625m0 0H12m3.75 0l-3.75-3.75M12 17.25v-2.625" />
  </svg>
);

const CheckIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className || "w-5 h-5"}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
  </svg>
);

const GOOGLE_CLIENT_ID = '345175519180-4mi947c49ifun5spn8fvtqtoi4l4kcre.apps.googleusercontent.com'; // Replace with your actual Client ID
const GMAIL_SCOPES = 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send';

function base64UrlDecode(str: string): string {
  try {
    let output = str.replace(/-/g, '+').replace(/_/g, '/');
    switch (output.length % 4) {
      case 0: break;
      case 2: output += '=='; break;
      case 3: output += '='; break;
      default: throw new Error('Illegal base64url string!');
    }
    const binaryString = window.atob(output);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  } catch (e) {
    console.error("Error decoding base64url string:", e, "Input (first 100 chars):", str.substring(0,100));
    return "";
  }
}

const extractEmailBody = (payload: any): string => {
  let body = "";
  if (payload?.parts) {
    const textPart = payload.parts.find((part: any) => part.mimeType === 'text/plain');
    if (textPart && textPart.body?.data) {
      body = base64UrlDecode(textPart.body.data);
    } else {
      const htmlPart = payload.parts.find((part: any) => part.mimeType === 'text/html');
      if (htmlPart && htmlPart.body?.data) {
        body = base64UrlDecode(htmlPart.body.data);
        const doc = new DOMParser().parseFromString(body, 'text/html');
        body = doc.body.textContent || "";
      } else {
         const anyTextPart = payload.parts.find((part: any) => part.body?.data && part.mimeType?.startsWith('text/'));
         if (anyTextPart) body = base64UrlDecode(anyTextPart.body.data);
      }
    }
  } else if (payload?.body?.data) {
    body = base64UrlDecode(payload.body.data);
    if (payload.mimeType === 'text/html') {
        const doc = new DOMParser().parseFromString(body, 'text/html');
        body = doc.body.textContent || "";
    }
  }
  return body.trim();
};


const App: React.FC = () => {
  const [userMessage, setUserMessage] = useState<string>('');
  const [generatedEmail, setGeneratedEmail] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const [googleUser, setGoogleUser] = useState<DecodedCredential | null>(null);
  const [gisApiReady, setGisApiReady] = useState(false);
  const [gapiReady, setGapiReady] = useState(false);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const tokenClientRef = useRef<any>(null);

  const [unreadEmails, setUnreadEmails] = useState<GmailEmail[]>([]);
  const [selectedEmail, setSelectedEmail] = useState<GmailEmail | null>(null);
  const [isFetchingEmails, setIsFetchingEmails] = useState<boolean>(false);
  const [isSendingEmail, setIsSendingEmail] = useState<boolean>(false);
  const [gmailApiError, setGmailApiError] = useState<string | null>(null);

  const signInButtonRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (gisApiReady) return;
    const intervalId = setInterval(() => {
      if (window.google?.accounts?.id) {
        setGisApiReady(true);
        clearInterval(intervalId);
      }
    }, 100);
    return () => clearInterval(intervalId);
  }, [gisApiReady]);

  useEffect(() => {
    if (gapiReady || !gisApiReady) return;

    const script = document.querySelector('script[src="https://apis.google.com/js/api.js"]');
    const initializeGapi = () => {
        if (window.gapi && typeof window.gapi.load === 'function') {
            window.gapi.load('client', async () => {
                try {
                    await window.gapi.client.init({
                        discoveryDocs: ["https://www.googleapis.com/discovery/v1/apis/gmail/v1/rest"],
                    });
                    console.log("GAPI client initialized for Gmail.");
                    setGapiReady(true);
                } catch (e: any) {
                    console.error("Error initializing GAPI client:", e);
                    setGmailApiError(`Failed to initialize Gmail API client: ${e.message}`);
                }
            });
        } else {
             console.warn("window.gapi or window.gapi.load not available yet for GAPI init.");
        }
    };

    if (window.gapi && typeof window.gapi.load === 'function') {
        initializeGapi();
    } else if (script) {
        script.addEventListener('load', initializeGapi);
        return () => {
            if (script) script.removeEventListener('load', initializeGapi);
        };
    } else {
        console.error("GAPI script not found.");
        setGmailApiError("Gmail API script not found. Cannot load emails.");
    }
  }, [gapiReady, gisApiReady]);


  const handleCredentialResponse = useCallback((response: any) => {
    if (response.credential) {
      try {
        const decoded: DecodedCredential = jwtDecode(response.credential);
        setGoogleUser(decoded);
        setError(null);

        if (window.google?.accounts?.oauth2 && GOOGLE_CLIENT_ID) {
          tokenClientRef.current = window.google.accounts.oauth2.initTokenClient({
            client_id: GOOGLE_CLIENT_ID,
            scope: GMAIL_SCOPES,
            callback: (tokenResponse: AccessTokenResponse) => {
              if (tokenResponse.error) {
                console.error("Error getting access token:", tokenResponse.error, tokenResponse.error_description);
                setGmailApiError(`Failed to get Gmail access: ${tokenResponse.error_description || tokenResponse.error}. Please try signing out and in again, and ensure you grant permissions.`);
                setAccessToken(null);
                return;
              }
              if (tokenResponse.access_token) {
                setAccessToken(tokenResponse.access_token);
                if (window.gapi && window.gapi.client) {
                    window.gapi.client.setToken({ access_token: tokenResponse.access_token });
                } else {
                    console.warn("GAPI client not ready when setting token, will set later if needed.");
                }
                setGmailApiError(null);
              }
            },
          });

          if (tokenClientRef.current) {
            tokenClientRef.current.requestAccessToken({});
          }
        }
      } catch (e) {
        console.error("Error decoding JWT or initializing token client:", e);
        setError("Failed to process Google Sign-In or Gmail permissions.");
        setGoogleUser(null);
        setAccessToken(null);
      }
    } else {
      console.error("Google Sign-In error:", response);
      setError("Google Sign-In failed. Please try again.");
      setGoogleUser(null);
      setAccessToken(null);
    }
  }, []); // Empty dependency array is generally fine for GSI callbacks that don't depend on changing props/state for their definition

  useEffect(() => {
    if (gisApiReady && !googleUser) {
      if (!GOOGLE_CLIENT_ID) {
        setError("Google Client ID is not configured. Sign-In disabled.");
        return;
      }
      try {
        window.google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleCredentialResponse,
        });
        if (signInButtonRef.current && signInButtonRef.current.innerHTML === "") {
            window.google.accounts.id.renderButton(
              signInButtonRef.current,
              { theme: "outline", size: "large", type: "standard", text: "signin_with" }
            );
        }
      } catch (e: any) {
        setError(`Failed to initialize Google Sign-In: ${e.message}`);
      }
    } else if (gisApiReady && googleUser && signInButtonRef.current) {
        signInButtonRef.current.innerHTML = '';
    }
  }, [gisApiReady, googleUser, handleCredentialResponse]);

  const handleSignOut = useCallback(() => {
    if (googleUser && window.google?.accounts?.id) {
      // To force re-prompting for consent next time, you might consider:
      // window.google.accounts.id.revoke(googleUser.email, () => {
      //   console.log('User token revoked.');
      // });
      // Or disable auto sign-in for the next visit
      // window.google.accounts.id.disableAutoSelect();
    }
    setGoogleUser(null);
    setAccessToken(null);
    setUnreadEmails([]);
    setSelectedEmail(null);
    setGeneratedEmail('');
    setGmailApiError(null);
  }, [googleUser]);

  const handleLoadUnreadEmails = useCallback(async () => {
    if (!googleUser || !gapiReady) {
      setGmailApiError("Please sign in. Gmail client not ready.");
      return;
    }
    if (!accessToken) {
        if (tokenClientRef.current) {
            console.log("Access token missing, requesting...");
            tokenClientRef.current.requestAccessToken({prompt: 'consent'});
        } else {
            setGmailApiError("Access token missing and token client not ready. Please sign in again.");
        }
        return;
    }

    setIsFetchingEmails(true);
    setGmailApiError(null);
    setUnreadEmails([]);
    setSelectedEmail(null);

    try {
      if (window.gapi?.client?.getToken()?.access_token !== accessToken) {
          window.gapi.client.setToken({ access_token: accessToken });
      }

      const response = await window.gapi.client.gmail.users.messages.list({
        userId: 'me',
        q: 'is:unread',
        maxResults: 10,
      });

      const messages = response.result.messages || [];
      if (messages.length === 0) {
        setUnreadEmails([]);
        setIsFetchingEmails(false);
        return;
      }

      const emailPromises = messages.map(async (msg: any) => {
        const emailRes = await window.gapi.client.gmail.users.messages.get({
          userId: 'me',
          id: msg.id,
          format: 'full'
        });
        const headers = emailRes.result.payload.headers;
        const subjectHeader = headers.find((h: any) => h.name.toLowerCase() === 'subject');
        const fromHeader = headers.find((h: any) => h.name.toLowerCase() === 'from');
        const dateHeader = headers.find((h: any) => h.name.toLowerCase() === 'date');

        return {
          id: emailRes.result.id,
          threadId: emailRes.result.threadId,
          subject: subjectHeader ? subjectHeader.value : 'No Subject',
          snippet: emailRes.result.snippet,
          from: fromHeader ? fromHeader.value : 'Unknown Sender',
          body: extractEmailBody(emailRes.result.payload),
          date: dateHeader ? new Date(dateHeader.value).toLocaleString() : 'Unknown Date',
        };
      });

      const fetchedEmails: GmailEmail[] = (await Promise.all(emailPromises)).filter(email => email.body);
      setUnreadEmails(fetchedEmails);
    } catch (e: any) {
      console.error("Error loading Gmail emails:", e);
      const errorMsg = e.result?.error?.message || e.message || 'Unknown error';
      setGmailApiError(`Failed to load emails: ${errorMsg}`);
      if (e.result?.error?.status === 'PERMISSION_DENIED' || e.status === 401 || e.status === 403) {
        setGmailApiError("Permission denied for Gmail. Try signing out, then sign in again and ensure you grant access when prompted.");
        if (tokenClientRef.current) tokenClientRef.current.requestAccessToken({prompt: 'consent'});
      }
    } finally {
      setIsFetchingEmails(false);
    }
  }, [googleUser, accessToken, gapiReady]);

  const handleConvert = useCallback(async () => {
    if (!userMessage.trim()) {
      setError('Please enter your message or reply idea.');
      return;
    }
    setIsLoading(true);
    setError(null);
    setGeneratedEmail('');

    try {
      const email = await formalizeEmail(userMessage, selectedEmail?.body);
      setGeneratedEmail(email);
    } catch (e: any) {
      setError(e.message || 'Failed to generate email. Check Gemini API key.');
    } finally {
      setIsLoading(false);
    }
  }, [userMessage, selectedEmail]);

  const handleCopy = useCallback(() => {
    if (generatedEmail) {
      navigator.clipboard.writeText(generatedEmail)
        .then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        })
        .catch(err => {
          setError('Failed to copy email to clipboard.');
          console.error('Copy failed', err);
        });
    }
  }, [generatedEmail]);

  const handleSendViaGmail = useCallback(async () => {
    if (!googleUser || !accessToken || !gapiReady || !selectedEmail || !generatedEmail) {
      setGmailApiError("Cannot send email. Ensure you are signed in, an email is selected, and a reply is generated.");
      return;
    }
    setIsSendingEmail(true);
    setGmailApiError(null);

    try {
        if (window.gapi?.client?.getToken()?.access_token !== accessToken) {
            window.gapi.client.setToken({ access_token: accessToken });
        }

        const fromHeader = selectedEmail.from;
        const match = fromHeader.match(/<(.*)>/);
        const recipientEmail = match ? match[1] : fromHeader.trim();

        const subject = selectedEmail.subject.toLowerCase().startsWith("re:")
            ? selectedEmail.subject
            : `Re: ${selectedEmail.subject}`;

        const emailLines = [
            `To: ${recipientEmail}`,
            `From: ${googleUser.email}`,
            `Subject: ${subject}`,
            "Content-Type: text/plain; charset=utf-8",
            "MIME-Version: 1.0",
            "",
            generatedEmail,
        ];
        const rawEmail = emailLines.join("\r\n");

        const utf8Encoder = new TextEncoder();
        const encodedEmailBytes = utf8Encoder.encode(rawEmail);

        // --- UPDATED: More robust Uint8Array to binary string conversion for btoa ---
        let binaryString = "";
        const CHUNK_SIZE = 8192; // Process in chunks to avoid stack overflow
        // Node.js Buffer alternative (if running in Node.js environment, not browser):
        // binaryString = Buffer.from(encodedEmailBytes).toString('binary');
        // For browser environment:
        for (let i = 0; i < encodedEmailBytes.length; i += CHUNK_SIZE) {
            binaryString += String.fromCharCode.apply(null, Array.from(encodedEmailBytes.subarray(i, i + CHUNK_SIZE)));
        }
        // --- End of UPDATE ---

        let base64EncodedEmail = btoa(binaryString);
        base64EncodedEmail = base64EncodedEmail.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

        await window.gapi.client.gmail.users.messages.send({
            userId: 'me',
            resource: {
                raw: base64EncodedEmail,
                threadId: selectedEmail.threadId
            }
        });
        alert("Reply sent successfully via Gmail!");
        setGeneratedEmail('');
        const repliedEmailId = selectedEmail.id;
        setSelectedEmail(null);
        setUnreadEmails(prev => prev.filter(email => email.id !== repliedEmailId));
    } catch (e: any) {
        console.error("Error sending Gmail email:", e);
        setGmailApiError(`Failed to send email: ${e.result?.error?.message || e.message || 'Unknown error'}`);
    } finally {
        setIsSendingEmail(false);
    }
  }, [googleUser, accessToken, gapiReady, selectedEmail, generatedEmail]);


  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex flex-col items-center p-4 sm:p-8 text-slate-100">
      <header className="w-full max-w-4xl mb-6 text-center">
        <h1 className="text-4xl sm:text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-sky-400 to-blue-500">
          Email Formalizer AI
        </h1>
        <p className="text-slate-400 mt-2 text-lg">Transform casual notes, reply to emails professionally.</p>
        {googleUser && (
            <div className="mt-2 text-sm text-slate-300">
                Signed in as: {googleUser.name} ({googleUser.email})
                {gapiReady && accessToken && <span className="text-green-400 ml-2">(Gmail Ready)</span>}
                {gapiReady && !accessToken && <span className="text-yellow-400 ml-2">(Gmail Access Pending...)</span>}
                {!gapiReady && <span className="text-orange-400 ml-2">(Gmail Client Loading...)</span>}
            </div>
        )}
      </header>

      <section className="w-full max-w-4xl bg-slate-800/70 shadow-xl shadow-sky-500/10 rounded-xl p-6 sm:p-8 mb-8">
        <h2 className="text-2xl font-semibold text-sky-400 mb-4 text-center">Gmail Integration</h2>
        {!GOOGLE_CLIENT_ID && (
            <div className="text-center text-yellow-400 bg-yellow-900/30 border border-yellow-700 p-3 rounded-lg">
                <p className="font-semibold">Configuration Notice:</p>
                <p>Google Client ID is not configured.</p>
                <p>Gmail integration features require this setup and will be disabled.</p>
            </div>
         )}

        {googleUser ? (
          <div className="text-center">
            <button
              onClick={handleLoadUnreadEmails}
              disabled={!gapiReady || !accessToken || isFetchingEmails}
              className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-600 text-white font-semibold rounded-lg shadow-md mr-4 transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 disabled:cursor-not-allowed"
            >
              {isFetchingEmails ? <LoadingSpinner className="w-5 h-5 mr-2 inline"/> : null}
              Load Unread Emails
            </button>
            <button
              onClick={handleSignOut}
              className="px-5 py-2.5 bg-red-600 hover:bg-red-500 text-white font-semibold rounded-lg shadow-md transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-opacity-50"
            >
              Sign Out
            </button>
            {gmailApiError && <p className="text-red-400 mt-3">{gmailApiError}</p>}

            {isFetchingEmails && !unreadEmails.length && <p className="text-slate-300 mt-4">Fetching emails...</p>}

            {unreadEmails.length > 0 && (
              <div className="mt-6 text-left">
                <h3 className="text-lg font-semibold text-sky-300 mb-2">Select an email to reply to:</h3>
                <div className="max-h-96 overflow-y-auto bg-slate-700/50 p-3 rounded-lg border border-slate-600">
                  {unreadEmails.map(email => (
                    <div
                      key={email.id}
                      onClick={() => { setSelectedEmail(email); setUserMessage(''); setGeneratedEmail(''); setGmailApiError(null);}}
                      className={`p-3 mb-2 rounded-md cursor-pointer border border-transparent email-item ${selectedEmail?.id === email.id ? 'bg-sky-700/50 shadow-lg border-sky-600' : 'hover:border-sky-600 hover:bg-slate-700'}`} // Enhanced selected style
                      role="button"
                      tabIndex={0}
                      onKeyPress={(e) => {if(e.key === 'Enter'){setSelectedEmail(email); setUserMessage(''); setGeneratedEmail(''); setGmailApiError(null);}}}
                      aria-pressed={selectedEmail?.id === email.id}
                    >
                      <div className="font-semibold text-sm">{email.from}</div>
                      <div className={`text-xs ${selectedEmail?.id === email.id ? 'text-slate-100' : 'text-slate-300'}`}>{email.subject}</div>
                      <p className={`text-xs mt-1 truncate ${selectedEmail?.id === email.id ? 'text-slate-200' : 'text-slate-400'}`}>{email.snippet}</p>
                      <div className={`text-xs mt-1 ${selectedEmail?.id === email.id ? 'text-slate-200' : 'text-slate-400'}`}>{email.date}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {unreadEmails.length === 0 && !isFetchingEmails && googleUser && gapiReady && accessToken &&
                <p className="text-slate-400 mt-4">No unread emails found, or none loaded yet. Click "Load Unread Emails".</p>
            }

          </div>
        ) : (
          <div className="text-center">
            <p className="text-slate-300 mb-4">Sign in with Google to load and reply to your Gmail emails.</p>
            <div ref={signInButtonRef} id="gsiButton" className="gsi-button-container flex justify-center min-h-[40px]">
                {GOOGLE_CLIENT_ID && !gisApiReady && <p className="text-slate-400">Initializing Google Sign-In...</p>}
                {GOOGLE_CLIENT_ID && gisApiReady && <div className="min-h-[40px]"></div>}
                {!GOOGLE_CLIENT_ID && <p className="text-sm text-yellow-500 mt-2">Google Sign-In cannot be displayed: Client ID is missing.</p>}
            </div>
          </div>
        )}
      </section>

      <main className="w-full max-w-4xl bg-slate-800 shadow-2xl shadow-sky-500/10 rounded-xl p-6 sm:p-10">
        {selectedEmail && (
          <div className="mb-6 p-4 bg-slate-700/70 rounded-lg border border-sky-700">
            <h3 className="text-lg font-semibold text-sky-300">Replying to:</h3>
            <p className="text-sm"><span className="font-medium text-slate-300">From:</span> {selectedEmail.from}</p>
            <p className="text-sm"><span className="font-medium text-slate-300">Subject:</span> {selectedEmail.subject}</p>
            <p className="text-sm mt-1 text-slate-400 italic truncate">"{selectedEmail.snippet}"</p>
            <button onClick={() => {setSelectedEmail(null); setGeneratedEmail(''); setUserMessage('');}} className="text-xs text-red-400 hover:text-red-300 mt-2">Clear Selection</button>
          </div>
        )}
        <div className="grid md:grid-cols-2 gap-8">
          <div className="flex flex-col space-y-4">
            <div>
              <label htmlFor="userMessage" className="block text-md font-semibold text-sky-400 mb-2">
                Your Informal Message <span className="text-sm text-slate-400">({selectedEmail ? "reply idea" : "new email idea"}):</span>
              </label>
              <textarea
                id="userMessage"
                value={userMessage}
                onChange={(e) => setUserMessage(e.target.value)}
                rows={10}
                className="w-full p-3 bg-slate-700 border border-slate-600 rounded-lg shadow-sm focus:ring-2 focus:ring-sky-500 focus:border-sky-500 text-slate-100 placeholder-slate-400 resize-none"
                placeholder={selectedEmail ? "e.g., sounds good, let's do that." : "e.g., hey team, meeting next week?"}
                aria-label="Your informal message or reply idea"
              />
            </div>
            <button
              onClick={handleConvert}
              disabled={isLoading || !userMessage.trim() || isSendingEmail}
              className="w-full flex items-center justify-center px-6 py-3 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-600 text-white font-semibold rounded-lg shadow-md hover:shadow-lg transition-all duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-sky-500 focus:ring-opacity-50 disabled:cursor-not-allowed"
              aria-busy={isLoading}
            >
              {isLoading ? (
                <>
                  <LoadingSpinner className="w-5 h-5 mr-2" />
                  Formalizing...
                </>
              ) : (
                selectedEmail ? 'Formalize Reply' : 'Formalize New Email'
              )}
            </button>
          </div>

          <div className="flex flex-col space-y-4">
            <div>
              <label htmlFor="generatedEmail" className="block text-md font-semibold text-sky-400 mb-2">
                Generated Official Email {selectedEmail ? "Reply Body" : "Content"}:
              </label>
              <div className="relative">
                <textarea
                  id="generatedEmail"
                  value={generatedEmail}
                  readOnly
                  rows={10}
                  className="w-full p-3 bg-slate-700 border border-slate-600 rounded-lg shadow-sm text-slate-100 placeholder-slate-400 resize-none"
                  placeholder="Your professional email content will appear here..."
                  aria-label="Generated official email"
                  aria-live="polite"
                />
                {generatedEmail && !isSendingEmail && (
                  <button
                    onClick={handleCopy}
                    title={copied ? "Copied!" : "Copy to clipboard"}
                    aria-label={copied ? "Email copied to clipboard" : "Copy email to clipboard"}
                    className="absolute top-3 right-3 p-2 bg-slate-600 hover:bg-slate-500 rounded-md text-slate-300 hover:text-sky-400 transition-colors duration-200"
                  >
                    {copied ? <CheckIcon className="w-5 h-5 text-green-400" /> : <CopyIcon className="w-5 h-5" />}
                  </button>
                )}
              </div>
            </div>
             {googleUser && generatedEmail && selectedEmail && (
                <button
                    onClick={handleSendViaGmail}
                    disabled={isSendingEmail || !accessToken || !gapiReady}
                    className="w-full flex items-center justify-center px-6 py-3 bg-green-600 hover:bg-green-500 disabled:bg-slate-600 text-white font-semibold rounded-lg shadow-md transition-all duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-opacity-50 disabled:cursor-not-allowed"
                >
                    {isSendingEmail ? <><LoadingSpinner className="w-5 h-5 mr-2"/> Sending...</> : "Send Reply via Gmail"}
                </button>
            )}
             {googleUser && generatedEmail && !selectedEmail && (
                <p className="text-sm text-slate-400 text-center">Select an email from the list above to enable "Send Reply via Gmail". For new emails, copy the content and send via your preferred email client.</p>
             )}
          </div>
        </div>

        {error && (
          <div role="alert" className="mt-6 text-center text-red-400 bg-red-900/30 border border-red-700 p-4 rounded-lg shadow-md">
            <p className="font-semibold">Application Error:</p>
            <p>{error}</p>
            {error.includes("API_KEY") && !error.includes("Google Client ID") && <p className="mt-2 text-sm text-slate-400">Please ensure your Gemini API key is correctly configured as an environment variable (<code>process.env.API_KEY</code>).</p>}
            {error.includes("Google Client ID") && <p className="mt-2 text-sm text-slate-400">Please ensure your Google Client ID is correctly configured or there's an issue with the GSI library.</p>}
          </div>
        )}
      </main>

      <footer className="mt-12 text-center text-sm text-slate-500">
        Powered by <a href="https://deepmind.google/technologies/gemini/" target="_blank" rel="noopener noreferrer" className="text-sky-500 hover:underline">Gemini AI</a> & Google.
      </footer>
    </div>
  );
};

export default App;