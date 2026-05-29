import { LoginSection } from './_components/LoginSection';
import { Wordmark } from './_components/Wordmark';

export default function HomePage(): React.ReactElement {
  return (
    <main
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        gap: '24px',
      }}
    >
      <Wordmark />
      <LoginSection />
    </main>
  );
}
