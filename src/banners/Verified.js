import { VERIFY_FAILURE_REASON } from "../hooks/use-verified-pass";

import "./Banner.css";

export default function Verified({ person, reset }) {
  const { givenName, familyName, dob } = person;

  return (
    <div className="Banner-Container">
      <div className="Banner" style={{ background: "#06d6a0", color: "white" }}>
        <div className="Banner-Header">NZ Covid Passport Validated</div>
        <div className="Banner-Contents">
          <span style={{ fontSize: 22, marginBottom: 8, display: 'block' }}>
            <b>
              {givenName} {familyName}
            </b>
            <br />
            <b>Date of Birth:</b> {dob}
          </span>
          <button className="Banner-Button" onClick={reset}>
            Scan Another
          </button>
        </div>
      </div>
    </div>
  );
}
