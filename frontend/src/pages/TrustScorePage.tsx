import Page from "../components/layout/Page";
import TrustPanel from "../components/TrustPanel";

export default function TrustScorePage() {
  return (
    <Page
      title="Trust score"
      description="A deep dive on this session: the current score, every factor's contribution, and what the engine did with it."
    >
      <TrustPanel />
    </Page>
  );
}
