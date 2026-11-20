document.addEventListener('DOMContentLoaded',function(){
  var b=document.querySelector('.burger'),n=document.querySelector('.nav');
  if(b&&n)b.addEventListener('click',function(){var o=n.classList.toggle('open');b.setAttribute('aria-expanded',o)});
  var y=document.getElementById('yr');if(y)y.textContent=new Date().getFullYear();
  // cosmetic only: forms never leave the browser with anything useful
  document.querySelectorAll('form[data-demo]').forEach(function(f){
    f.addEventListener('submit',function(e){e.preventDefault();f.reset();
      var m=f.querySelector('.form-msg');if(m){m.hidden=false}});
  });
});