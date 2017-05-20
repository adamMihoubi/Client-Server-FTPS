open CLessType
open ASMType

(**Fonctions auxiellieres du TP4*)
(*****************************************************************)
let rec addreg varl sp = function
|[] -> (varl,sp)
|v :: t -> addreg (varl @ [(v,ARI(-(sp+8),RBP))]) (sp+8) t
;;

let rec subListe a b  = function
    [] -> failwith "sublist"
    | h :: t -> 
     let taille = if b=0 then [] else subListe (a-1) (b-1) t in
     if a>0 then taille else h ::taille
;;

let rec liaison varl sp liste tab = match liste with
|[]->(varl,sp)
|t::q -> liaison(varl@[(t,R (List.hd tab))]) (sp-8) q (List.tl tab)
;;
(*****************************************************************)

(**Fontion auxillieres au TP5**)
(*****************************************************************)
(*Exercice 1 - TP5*)
let rec taille_expr = function 
| Const i -> 1
| Var v -> 1
| String s -> 1
| BOperator(eg,op,ed) -> 1 + taille_expr eg + 1 + taille_expr ed
| Seq(seq) -> 1 + List.fold_left (fun x a -> x + taille_expr a) 0 seq 
| Comp(eg,cmp,ed) -> 1 + taille_expr eg + 1 +taille_expr ed
| Call(label,args) -> 1 + 1 + List.fold_left (fun x a -> x + taille_expr a) 0 args 
| UOperator(op,exp) -> 1 + 1 + taille_expr exp
| Set (x,e) -> 1 + 1 + taille_expr e
;; 

(*Exercice 2 - TP5*)
let rec taille_stat = function
| Expr e -> taille_expr e
| BlockStat(varl,s) -> 1 + List.length varl + List.fold_left (fun x a -> x + taille_stat a) 0 s 
| IfStat(e, s1, s2) ->1 + taille_expr e + taille_stat s1 +taille_stat s2
| ReturnStat None -> 1
| ReturnStat (Some(e)) -> 1 + taille_expr e
| WhileStat(exp,s) -> 1 + taille_expr exp + taille_stat s 
;;

let taille_dec = function
| VarDec(_) -> 1
| FunDec(name,args,s) -> 1 + 1 + List.length args + taille_stat s
;;

(* Exercice 3 - TP5 *)
let check_inline = function 
| s -> let arg,s = getFunDec s in 
       let longueur = List.length arg + taille_stat s  in
       longueur < 40 
;;

(********************************************************************)


(**Generate **)
let rec generate_asm_expression varl sp  e il = match e with
  (* *)
  | Const i -> il |% MOV(C i, R RAX) 
  | BOperator(eg,Add,ed) ->
     let il2 = generate_asm_expression varl sp eg il
     |% PUSH (R RAX) in
     generate_asm_expression varl (sp+8) ed il2
     |% ADD (ARI (0,RSP), R RAX)
     |% ADD (C 8, R RSP)
  | BOperator(eg,Mult,ed) ->
     let il2 = generate_asm_expression varl sp eg il
     |% PUSH (R RAX) in
     generate_asm_expression varl (sp+8) ed il2
     |% MUL (ARI (0,RSP), R RAX)
     |% ADD (C 8, R RSP)

  | BOperator(eg,Sub,ed) ->
     let il2 = generate_asm_expression varl sp ed il
     |% PUSH (R RAX) in
     generate_asm_expression varl (sp+8) eg il2
     |% SUB (ARI (0,RSP), R RAX)
     |% ADD (C 8, R RSP)
	
   | BOperator(eg,And,ed) ->
     let il2 = generate_asm_expression varl sp eg il
     |% PUSH (R RAX) in
     generate_asm_expression varl (sp+8) ed il2
     |% AND (ARI (0,RSP), R RAX)
     |% ADD (C 8, R RSP)

   | BOperator(eg,Or,ed) ->
     let il2 = generate_asm_expression varl sp eg il
     |% PUSH (R RAX) in
     generate_asm_expression varl (sp+8) ed il2
     |% OR (ARI (0,RSP), R RAX)
     |% ADD (C 8, R RSP)

   | BOperator(eg,Div,ed) ->
     let il2 = generate_asm_expression varl sp ed il
     |% PUSH (R RAX) in
     generate_asm_expression varl (sp+8) eg il2
     |% DIV (ARI (0,RSP), R RAX)
     |% ADD (C 8, R RSP)

  | BOperator(eg,Mod,ed) -> (*let modulo = fresh_lbl "modulo" in
     let fin = fresh_lbl "fin_modulo" in *)
     let il2 = generate_asm_expression varl sp ed il
     |% PUSH (R RAX) in 
     generate_asm_expression varl (sp+8) eg il2
     |% DIV (ARI (0,RSP), R RAX)
     |% MOV (R RDX, R RAX)
     (*|% Label modulo
     |% SUB (ARI (0,RSP), R RAX)
     |% TEST (ARI (0,RSP), R RAX)
     |% JZ (L fin)
     |% JMP (L modulo) 
     |% Label fin*)
     |% ADD (C 8, R RSP)

  
  
  | Seq(seq) -> List.fold_left (fun il2 s->generate_asm_expression varl sp s il2) il seq

  | UOperator(Not,exp)-> generate_asm_expression varl sp exp il 
	|% NOT (R RAX)
    
  | UOperator(MinusM,exp)-> generate_asm_expression varl sp exp il 
	|% NEG (R RAX)
    
  | Comp(eg,EQ,ed) -> 
	let il2 = generate_asm_expression varl sp eg il
    |% PUSH (R RAX) in
    generate_asm_expression varl (sp+8) ed il2
    |% CMP (ARI (0,RSP),R RAX)
    |% SETE (R AL)
    |% ADD (C 8, R RSP)
  
  | Comp(eg,NEQ,ed) -> 
	let il2 = generate_asm_expression varl sp eg il
    |% PUSH (R RAX) in
    generate_asm_expression varl (sp+8) ed il2
	|% CMP (ARI (0,RSP),R RAX)
    |% SETNE (R AL)
    |% ADD (C 8, R RSP)

   | Comp(eg,LL,ed) -> 
	let il2 = generate_asm_expression varl sp eg il
    |% PUSH (R RAX) in
    generate_asm_expression varl (sp+8) ed il2
	|% CMP (ARI (0,RSP),R RAX)
    |% SETG (R AL)
    |% ADD (C 8, R RSP)

   | Comp(eg,LE,ed) -> 
	let il2 = generate_asm_expression varl sp eg il
    |% PUSH (R RAX) in
    generate_asm_expression varl (sp+8) ed il2
    |% CMP (ARI (0,RSP),R RAX)
    |% SETNS (R AL)
    |% ADD (C 8, R RSP)

  | String s ->
     let sl = addr_lbl_of_string s in
     il |% LEAQ (sl, R RAX)

  | Var x -> let pos = List.assoc x varl in 
     il |% MOV (pos, R RAX)

  | Set (x,e) -> let pos = List.assoc x varl in
	let il2 = generate_asm_expression varl sp e il in
	il2 |% MOV (R RAX , pos)

  | Call(s,[]) -> il |% CALL (L s) 

  | Call(label,args) when check_inline label -> let arglist,state = getFunDec label in
				let nvarl, nsp = addreg varl sp arglist in
				let lab = (fresh_lbl "main") in
				let il2 = List.fold_left (fun il2 s -> generate_asm_expression nvarl nsp s il2|% PUSH (R RAX)) il args 
				in					 
				generate_asm_statement nvarl nsp lab state il2
				|% ADD (C nsp, R RSP)
				|% Label (lab)
				


  | Call(s,args) -> let rec myfoldLeft varl sp il tab = function
                          |[]   -> il
                          |t::s -> myfoldLeft varl sp (generate_asm_expression varl sp t il |% MOV (R RAX,R (List.hd tab))) (List.tl tab) s
                          in 
			  let listeRegistre = subListe 0 (List.length args) ([RDI ; RSI ; RDX ; RCX ; R8 ; R9 ]) in
			  let prog = myfoldLeft varl sp il listeRegistre args in
                              (
                              prog
                                          |% ADD (C sp,R RSP)
                                          |% CALL (L s)
                                          |% SUB (C sp,R RSP)
	                                 
			      )
                               
 
					
					
					
	
	

  

    
and generate_asm_statement varl sp  returnLabel s il = match s with
  (* *)

  | Expr exp -> generate_asm_expression varl sp exp il
  
  | BlockStat([],sl) ->
     List.fold_left (fun il2 s ->
         generate_asm_statement varl sp  returnLabel s il2) il sl 
         

  | BlockStat(varll, sl) -> let sp2 = sp in 
				let cp = addreg varl sp2 varll in
				let newsp = (snd cp)-sp in
				let il3 = il |% SUB(C newsp, R RSP) in
				(List.fold_left (fun il2 s -> generate_asm_statement (fst cp)(snd cp)  returnLabel s il2) il3 sl)
				|% ADD (C newsp, R RSP)

  | ReturnStat None when returnLabel <> "" ->
     (il
	 |% ADD (C sp,R RSP)
	 |% POP (R RBP)
	 |% RET
     )
			               
  | ReturnStat None ->
     (il
	 |% ADD (C sp,R RSP)
	 |% POP (R RBP)
	 |% RET
     )
  
  | ReturnStat (Some(e)) when returnLabel <> "" ->
     let il2 = generate_asm_expression varl sp e il in
     generate_asm_statement varl sp  returnLabel (ReturnStat None) il2
     |% JMP (L returnLabel)
     

  | ReturnStat (Some(e)) ->
     let il2 = generate_asm_expression varl sp e il in
     generate_asm_statement varl sp  returnLabel (ReturnStat None) il2

  | IfStat(e,s1,s2) ->
     let le = fresh_lbl "if_end"
     and lf = fresh_lbl "if_else" in 
     let il2 = generate_asm_expression varl sp e il
	       |% TEST (R RAX, R RAX)
	       |% JZ (L lf) in
     let il3 = generate_asm_statement varl sp returnLabel s1 il2
	 |% JMP (L le)
	       |% Label lf in
     generate_asm_statement varl sp  returnLabel s2 il3
     |% Label le
     
   |WhileStat(exp,s) -> 
	let lw = fresh_lbl "debut_boucle"
   	and le = fresh_lbl "fin_while" in
	let il2 = il |% Label lw in
    let il3 = generate_asm_expression varl sp exp il2 
    	|% TEST (R RAX, R RAX)
    	|% JZ(L le) in
    generate_asm_statement varl sp  returnLabel s il3
    	|% JMP (L lw)
        |% Label le
        
    
;;                         
       

let generate_asm_top varl il = function
  | VarDec(_) -> il
  (* les variables globals sont déjà geré dans le fichier compilo.ml.
       On ne fait donc rien ici. *)
   
  | FunDec(name,[],s) ->
    let il2= il
     |% Label name
     |% PUSH (R RBP)
     |% MOV (R RSP, R RBP) in
    generate_asm_statement varl 0 "" s il2 
    

  | FunDec(name,args,s) when List.length(args)>6-> 
     il
     |% Label name
     |% PUSH (R RBP)
     |% MOV (R RSP, R RBP) 

  | FunDec(name,args,s) -> 
    let il2= il
     |% Label name
     |% PUSH (R RBP)
     |% MOV (R RSP, R RBP) 
    in let sp = -16 in
    let registre = [RDI;RSI;RDX;RCX;R8;R9] in 
    let couple = liaison [] sp args registre in 
    generate_asm_statement (fst couple) 0 "" s il2

    
  
    
