$(                          $( BEGIN EXAMPLE.MM - Metamath proof file $)
                            $( Replace this with your actual proof.     $)

  $( Declare the formal system tokens $)
  $c wff |- ( ) -> -. $. $( connectives $)
  $v ph ps ch $.         $( propositional variables $)

  $( Variable type hypotheses $)
  wph $f wff ph $.
  wps $f wff ps $.
  wch $f wff ch $.

  $( Axioms $)
  ax-1 $a |- ( ph -> ( ps -> ph ) ) $.
  ax-2 $a |- ( ( ph -> ( ps -> ch ) ) -> ( ( ph -> ps ) -> ( ph -> ch ) ) ) $.
  ax-3 $a |- ( ( -. ph -> -. ps ) -> ( ps -> ph ) ) $.
  ax-mp $a |- ps $=
    wph wps ax-mp.1 ax-mp.2 $.
    $( Modus ponens: from |- ph and |- ( ph -> ps ) infer |- ps $)
    ${ ax-mp.1 $e |- ph $. ax-mp.2 $e |- ( ph -> ps ) $. $}

  $( A simple lemma $)
  thm-lem $p |- ( ph -> ph ) $=
    wph wps ax-1 wph wph wps ax-1 ax-2 ax-mp ax-mp $.

  $( Main theorem: double negation introduction $)
  thm-main $p |- ( ph -> -. -. ph ) $=
    ( wn ax-3 ) ABAB $.

$(                                                                      $)
$(  END OF EXAMPLE.MM                                                   $)
$(  Adapt claim IDs in graph.json to match your theorem labels above.   $)
