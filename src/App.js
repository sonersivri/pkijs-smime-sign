import React from 'react';
import './App.css';
import EmailSigner from './EmailSigner';
import EmailVerifier from './EmailVerifier';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <EmailSigner />
        <EmailVerifier />
      </header>
    </div>
  );
}

export default App;
