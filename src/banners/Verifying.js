import { Spinner } from "./Spinner";

import './Banner.css';

export default function Verifying() {
  return (
    <div className="Banner-Container">
      <div className="Banner" style={{ background: '#ffd166' }}>
        <div className="Banner-Header">Verifying NZ Covid Passport</div>
        <div className="Banner-Contents">
          <Spinner />
        </div>
      </div>
    </div>
  );
}
