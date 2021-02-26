import React, { useState, useEffect, useContext } from 'react';
import {useHistory} from 'react-router-dom'
import * as sessionActions from '../../store/session';
import { useDispatch, useSelector } from 'react-redux';
import { useMenu } from '../../context/MenuContext';
import { Redirect } from 'react-router-dom';
import { getList } from '../../store/dashboard';
import { createTask } from '../../store/dashboard'
import './SliderMenu.css'

function SliderMenu() {
  const dispatch = useDispatch();
  const history = useHistory();
  const { menu, setMenu } = useMenu()
  const WholeMenu = useMenu()
  const sessionUser = useSelector(state => state.session.user);
  const taskItems = useSelector(state => state.dashboard.list)
  const taskItemsArray = Object.values(taskItems)
  const [singleStep, setSingleStep] = useState("")
  const [morning, setMorning] = useState(false)
  const [night, setNight] = useState(false)
  const [mon, setMon] = useState(false)
  const [tues, setTues] = useState(false)
  const [wed, setWed] = useState(false)
  const [thur, setThur] = useState(false)
  const [fri, setFri] = useState(false)
  const [sat, setSat] = useState(false)
  const [sun, setSun] = useState(false)
  const [tags, setTags] = useState("")
  const [lengthInMin, setLengthInMin] = useState(0)
  const [type, setType] = useState("")
  const [startDate, setStartDate] = useState(null)
  const [emptyDate, setEmptyDate] = useState(null)
  const [sizeInFlOz, setSizeInFlOz] = useState(0)
  const [activeIngredients, setActiveIngredients] = useState("")

  const updateStep = (e) => setSingleStep(e.target.value);
  const isMorning = (e) => setMorning(e.target.value);
  const isNight = (e) => setNight(e.target.value)
  const isMon = (e) => setMon(e.target.value)
  const isTues = (e) => setTues(e.target.value)
  const isWed = (e) => setWed(e.target.value)
  const isThur = (e) => setThur(e.target.value)
  const isFri = (e) => setFri(e.target.value)
  const isSat = (e) => setSat(e.target.value)
  const isSun = (e) => setSun(e.target.value)
  const isTags = (e) => setTags(e.target.value)
  const isTime = (e) => setLengthInMin(e.target.value)
  const isType = (e) => setType(e.target.value)
  const isStartDate = (e) => setStartDate(e.target.value)
  const isEmptyDate = (e) => setEmptyDate(e.target.value)
  const isSize = (e) => setSizeInFlOz(e.target.value)
  const isIngredients = (e) => setActiveIngredients(e.target.value)

  const handleSubmit = async (e) => {
    e.preventDefault();

    const payload = {
      userId: sessionUser.id,
      singleStep,
      tags,
      lengthInMin,
      type,
      startDate,
      emptyDate,
      sizeInFlOz,
      mon,
      tues,
      wed,
      thur,
      fri,
      sat,
      sun,
      night,
      morning,
      activeIngredients,
    };


    const step = await dispatch(createTask(payload, sessionUser.id));
    if(!step) {
      console.log("ITEM ADDED")
    }
  }



  if (!sessionUser) return (
    <Redirect to="/login" />
  );

  const divStyle = {
    width: menu === 'open' ? "250px" : "0px",
  };

  const obtnStyle = {
    visibility: menu === 'open' ? "hidden" : "visible",
  };

  return (
    <>

    <div id="mySidebar" 
    className="sidebar"
    style={divStyle}
    
    >
        <a href="javascript:void(0)" className="closebtn" onClick={() => setMenu('closed')}>&times;</a>
        <div className="add-product-div">
        <h3 className="add-product-section-title">Add a Step</h3>
        <form onSubmit={handleSubmit}>

        <div className="add-product-form-card">
        <input type="hidden" name="_csrf" value="csrfToken" />
          <input type="text"
          placeholder="name of product"
          value={singleStep}
          onChange={updateStep} />
          <button type="submit">Add A Step</button>
          </div>

          <div className="add-product-form-card">
          <input type="checkbox"
          id="morning"
          name="morning"
          value="morning" />
          <label for="morning">morning</label>
          </div>
          <div className="add-product-form-card">
          <input type="checkbox" id="evening" name="evening" value="evening"></input>
          <label for="evening">evening</label>
          </div>
          <p className="add-product-section-title">Which days?</p>
          <div className="add-product-form-card">
          <input type="checkbox" id="monday" name="monday" value="monday"></input>
          <label for="monday">monday</label>
          </div>
          <div className="add-product-form-card">
          <input type="checkbox" id="tuesday" name="tuesday" value="tuesday"></input>
          <label for="tuesday">tuesday</label>
          </div>
          <div className="add-product-form-card">
          <input type="checkbox" id="wednesday" name="wednesday" value="wednesday"></input>
          <label for="wednesday">wednesday</label>
          </div>
          <div className="add-product-form-card">
          <input type="checkbox" id="thursday" name="thursday" value="thursday"></input>
          <label for="thursday">thursday</label>
          </div>
          <div className="add-product-form-card">
          <input type="checkbox" id="friday" name="friday" value="friday"></input>
          <label for="friday">friday</label>
          </div>
          <div className="add-product-form-card">
          <input type="checkbox" id="saturday" name="saturday" value="saturday"></input>
          <label for="saturday">saturday</label>
          </div>
          <div className="add-product-form-card">
          <input type="checkbox" id="sunday" name="sunday" value="sunday"></input>
          <label for="sunday">sunday</label>
          </div>
        </form>
        </div>
    </div>

  <div id="main-menu"
    style={{marginLeft: menu === "open" ? "0px" : "250px" }}
  >
      <button 
      className="openbtn" 
      id="openbtn" 
      style={obtnStyle}
      onClick={() => setMenu('open')}
      
      >&#9776; +</button>
</div>
</>
    )
};

export default SliderMenu;