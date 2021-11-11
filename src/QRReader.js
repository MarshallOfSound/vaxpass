import ReactQrReader from 'react-qr-reader'

import { useWindowSize } from './hooks/use-window-size';

export default function QRReader({ onCode }) {
  const windowSize = useWindowSize();

  return (
    <div style={{
      height: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: '#26547C'
    }}>
    <div style={{
      width: Math.min(windowSize.height, windowSize.width),
    }}>
      <ReactQrReader
        delay={300}
        onError={console.error}
        onScan={onCode}
        facingMode="environment"
      />
    </div>
    </div>
  )
}