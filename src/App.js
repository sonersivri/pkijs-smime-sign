import React from 'react';
import './App.css';
import EmailSigner from './EmailSignAndVerifier';
import EmailVerifier from './EmailVerifier';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <EmailSigner />
      </header>
    </div>
  );
}

export default App;
