import { useState, useMemo } from "react";

import QRReader from "./QRReader";
import { useVerifiedPass } from "./hooks/use-verified-pass";
import Verified from "./banners/Verified";
import Verifying from "./banners/Verifying";
import VerifyError from "./banners/VerifyError";

function App() {
  const [parsedQRCode, setQRCode] = useState();
  const validated = useVerifiedPass(parsedQRCode);

  const reset = useMemo(() => () => setQRCode(null), [setQRCode]);

  if (!parsedQRCode) {
    return <QRReader onCode={setQRCode} />;
  }

  if (!validated.complete) {
    return <Verifying />;
  }

  if (!validated.verified) {
    return <VerifyError reason={validated.reason} reset={reset} />;
  }

  return <Verified person={validated.person} reset={reset} />;
}

export default App;
