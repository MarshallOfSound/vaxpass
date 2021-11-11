import { VERIFY_FAILURE_REASON } from "../hooks/use-verified-pass";

import "./Banner.css";

const prettyErrors = {
  [VERIFY_FAILURE_REASON.INVALID_QR_CODE]: (
    <p>The QR code you presented was invalid or was not a NZ Covid Passport.</p>
  ),
  [VERIFY_FAILURE_REASON.PASS_EXPIRED]: (
    <p>
      The Covid Passport provided has expired, please obtain a new Covid
      Passport from My Covid Record.
    </p>
  ),
  [VERIFY_FAILURE_REASON.PASS_NOT_VALID_YET]: (
    <p>
      The Covid Passport provided is not valid yet but it will be at some point
      in the future.
    </p>
  ),
};

export default function VerifyError({ reason, reset }) {
  return (
    <div className="Banner-Container">
      <div className="Banner" style={{ background: "#EF476F", color: "white" }}>
        <div className="Banner-Header">Invalid Covid Passport</div>
        <div className="Banner-Contents">
          {prettyErrors[reason] || (
            <p>An unexpected verification issue occurred: {reason}</p>
          )}
          <button className="Banner-Button" onClick={reset}>Scan Another</button>
        </div>
      </div>
    </div>
  );
}
